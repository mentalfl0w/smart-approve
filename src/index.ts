/**
 * Smart Approve extension entry point.
 *
 * OMP Bash/Eval use same-name native wrappers. Pi keeps native tools and gates
 * them through tool_call; protected paths and tracked proc stdin use the same
 * pre-execution hook on both hosts.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  ExtensionAPI,
  ExtensionCtx,
  HostToolInfo,
  ToolCallEvent,
  ToolResultEvent,
} from "./types";
import { Logger } from "./logger";
import { detectLang, getI18n, makeLabel } from "./i18n";
import type { Lang } from "./i18n";
import { ProtectedPathMatcher, resolveFilesystemPathCandidates } from "./paths";
import { ConfigStore } from "./config";
import { AllowList } from "./allowlist";
import { SessionContextGatherer } from "./context";
import { HostResolver, ModelInvoker } from "./host";
import { AutoDecisionPolicy } from "./policy";
import { ModeManager, type CoverageSummary } from "./mode-manager";
import { BashToolGate, UNRESOLVED_CWD, collectCdTargets, isUnresolvedCwd } from "./bash-tool";
import { EvalToolGate } from "./eval-tool";
import { extractEvalWriteTargets } from "./eval-analyzer";
import { confirmWithRemember } from "./dialog";
import {
  applyProcServiceMode,
  forgetProcService,
  forgetSessionServices,
  getTrackedServiceCwd,
  procServiceKillName,
  procServiceModeChange,
  resolveTrackedServiceInput,
  sessionIdOf,
  setTrackedServiceCwd,
  type TrackedProcInput,
} from "./proc-input-guard.ts";

function findNativeTool(tools: HostToolInfo[] | undefined, name: string): HostToolInfo | undefined {
  return tools?.find((tool) => tool.name === name && tool.sourceInfo?.source === "builtin");
}

function collectProtectedTargets(event: ToolCallEvent): string[] {
  const targets = new Set<string>();
  const add = (value: unknown): void => {
    if (typeof value === "string" && value.trim()) targets.add(value.trim());
  };

  add(event.input.path);
  if (Array.isArray(event.input.paths)) {
    for (const target of event.input.paths) add(target);
  }
  if (event.toolName === "edit" && Array.isArray(event.input.edits)) {
    for (const operation of event.input.edits) {
      if (operation !== null && typeof operation === "object" && "rename" in operation) {
        add(operation.rename);
      }
    }
  }

  if (event.toolName === "apply_patch" || event.toolName === "edit") {
    const patch = typeof event.input.input === "string"
      ? event.input.input
      : typeof event.input._input === "string"
        ? event.input._input
        : "";
    for (const line of patch.split(/\r?\n/)) {
      const file = /^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$/.exec(line);
      if (file) add(file[1]);
      const moved = /^\*\*\* Move to:\s*(.+?)\s*$/.exec(line);
      if (moved) add(moved[1]);
    }
  }

  return [...targets];
}

function isHardBlockedFileTarget(target: string, cwd: string): boolean {
  return resolveFilesystemPathCandidates(target, cwd).some((candidate) =>
    /^(?:\/private)?\/etc\/(?:passwd|shadow|sudoers|hosts)(?:$|[./])/i.test(candidate) ||
    /^\/dev\/(?:sd[a-z]\d*|nvme\d+(?:n\d+)?(?:p\d+)?|disk\d+(?:s\d+)?|hd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|mmcblk\d+(?:p\d+)?|mapper\/[^/]+|md\d+|sg\d+|st\d+|nst\d+)$/i.test(candidate)
  );
}

/** Apply ordered literal chdir targets to a tracked service cwd. */
function applyCwdTargets(
  currentCwd: string,
  targets: string[],
  dynamic: boolean,
  conservativeEvalTargets: boolean,
): string {
  if (dynamic || isUnresolvedCwd(currentCwd)) return UNRESOLVED_CWD;
  let cwd = currentCwd;
  for (const target of targets) {
    if (conservativeEvalTargets && /[~$`]/.test(target)) return UNRESOLVED_CWD;
    const absolute = path.resolve(cwd, target);
    const candidates = resolveFilesystemPathCandidates(absolute, cwd);
    cwd = candidates[candidates.length - 1] ?? absolute;
    try {
      if (!fs.statSync(cwd).isDirectory()) return UNRESOLVED_CWD;
    } catch {
      return UNRESOLVED_CWD;
    }
  }
  return cwd;
}

function nextServiceCwd(input: TrackedProcInput, currentCwd: string): string {
  if (input.runtime === "shell") {
    const changes = collectCdTargets(input.command);
    return applyCwdTargets(currentCwd, changes.targets, changes.dynamic, false);
  }
  const changes = extractEvalWriteTargets(
    input.command,
    input.runtime === "python" ? "py" : "js",
  );
  return applyCwdTargets(currentCwd, changes.cwdPaths, changes.cwdDynamic, true);
}

/**
 * Smart Approve extension orchestrator.
 *
 * Thin by design: each concern lives in its own class; this class only
 * constructs the collaborators and routes the two interception surfaces
 * (shadowed tools + tool_call events) through them.
 */
class SmartApprove {
  private readonly logger: Logger;
  private readonly lang: Lang;
  private readonly t = getI18n(detectLang());
  private readonly configStore: ConfigStore;
  private readonly allowList: AllowList;
  private readonly pathMatcher: ProtectedPathMatcher;
  private readonly contextGatherer: SessionContextGatherer;
  private readonly modelInvoker: ModelInvoker;
  private readonly policy: AutoDecisionPolicy;
  private readonly coverage: CoverageSummary;
  private readonly modeManager: ModeManager;
  private bashGate: BashToolGate | undefined;
  private evalGate: EvalToolGate | undefined;
  private readonly eventGate = { bash: false, eval: false };
  private procInputEnabled = false;
  private hostSessionId: string | undefined;
  private toolsInitialized = false;

  constructor(private readonly pi: ExtensionAPI) {
    this.logger = new Logger();
    this.lang = detectLang();
    this.configStore = new ConfigStore(this.logger);
    this.allowList = new AllowList(this.configStore.allowListPath, this.logger);
    this.pathMatcher = new ProtectedPathMatcher(this.configStore.config.protectedPaths);
    this.contextGatherer = new SessionContextGatherer(this.logger);
    const host = new HostResolver(this.logger);
    this.modelInvoker = new ModelInvoker(
      host, this.logger,
      this.configStore.config.analysisTimeoutMs,
      this.configStore.config.rpcIdleTimeoutMs,
    );
    this.policy = new AutoDecisionPolicy(this.configStore.config);
    this.coverage = { bash: false, eval: false, procInput: "false", protectedPaths: false };
    this.modeManager = new ModeManager(this.configStore, this.logger, this.coverage);
  }

  /** Register host-specific gates, hooks and the slash command. */
  register(): void {
    if (!this.configStore.config.enabled) return;

    const shared = {
      config: this.configStore.config,
      allowList: this.allowList,
      contextGatherer: this.contextGatherer,
      modelInvoker: this.modelInvoker,
      policy: this.policy,
      logger: this.logger,
      lang: this.lang,
      t: this.t,
      protectedPathMatcher: this.pathMatcher,
    };
    const bashGate = new BashToolGate(shared);
    const evalGate = new EvalToolGate(shared);
    this.bashGate = bashGate;
    this.evalGate = evalGate;


    this.pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionCtx) => {
      if (event.toolName === "bash" && this.eventGate.bash && this.bashGate) {
        const authorization = await this.bashGate.authorize(event.input, ctx.signal, ctx);
        if (!authorization.allowed) {
          return { block: true, reason: authorization.result.content[0]?.text || "Blocked by Smart Approve" };
        }
      }
      if (event.toolName === "eval" && this.eventGate.eval && this.evalGate) {
        const authorization = await this.evalGate.authorize(event.input, ctx.signal, ctx);
        if (!authorization.allowed) {
          return { block: true, reason: authorization.result.content[0]?.text || "Blocked by Smart Approve" };
        }
      }
      if (event.toolName === "write" && this.procInputEnabled) {
        const processInput = resolveTrackedServiceInput(
          event.input.path,
          event.input.content,
          ctx.cwd || process.cwd(),
          sessionIdOf(ctx),
        );
        if (processInput) {
          const gate = processInput.runtime === "shell"
            ? this.bashGate
            : this.configStore.config.coverage.eval
              ? this.evalGate
              : undefined;
          if (gate) {
            const params = processInput.runtime === "shell"
              ? { command: processInput.command, cwd: processInput.cwd }
              : {
                  language: processInput.runtime === "python" ? "py" : "js",
                  code: processInput.command,
                  cwd: processInput.cwd,
                };
            const authorization = await gate.authorize(params, ctx.signal, ctx);
            if (!authorization.allowed) {
              return {
                block: true,
                reason: authorization.result.content[0]?.text || "Blocked by Smart Approve",
              };
            }
          }
        }
      }
      if (["write", "edit", "apply_patch", "ast_edit"].includes(event.toolName)) {
        return this.handleProtectedPaths(event, ctx);
      }
    });

    this.pi.on("tool_result", async (event: ToolResultEvent, ctx: ExtensionCtx) => {
      if (!this.procInputEnabled || event.toolName !== "write" || event.isError) return;
      const workspace = ctx.cwd || process.cwd();
      const modeChange = procServiceModeChange(event.input.path, event.input.content);
      if (modeChange) {
        // detached/persist services stay routable after the owner session
        // ends, so their classification is retained for the host lifetime.
        applyProcServiceMode(
          modeChange.name,
          modeChange.mode,
          workspace,
          sessionIdOf(ctx),
        );
        return;
      }
      const killedName = procServiceKillName(event.input.path);
      // A kill result is authoritative for the project-unique service, so it
      // forgets regardless of which session observed it.
      if (killedName) {
        forgetProcService(killedName, workspace);
        return;
      }

      const processInput = resolveTrackedServiceInput(
        event.input.path,
        event.input.content,
        workspace,
        sessionIdOf(ctx),
      );
      if (!processInput) return;
      const currentCwd = getTrackedServiceCwd(processInput.name, workspace);
      if (currentCwd === undefined) return;
      const nextCwd = nextServiceCwd(processInput, currentCwd);
      if (nextCwd !== currentCwd) {
        setTrackedServiceCwd(processInput.name, nextCwd, workspace);
      }
    });

    this.pi.on("session_start", async (_event, ctx: ExtensionCtx) => {
      this.initializeHostTools(ctx);
      ctx.ui.setStatus("smart-approve-mode", this.configStore.config.mode);
    });

    this.pi.registerCommand("smart-approve", {
      description: "Toggle or inspect smart-approve mode (auto/interactive)",
      handler: async (args: unknown, ctx: ExtensionCtx) => {
        this.handleCommand(args, ctx);
      },
    });

    this.pi.on("session_shutdown", async (_event, ctx: ExtensionCtx) => {
      // Named proc services are project-unique; session-lifetime registrations
      // are removed, while detached/persist services stay tracked for the
      // host lifetime because they remain publicly routable.
      forgetSessionServices(sessionIdOf(ctx) ?? this.hostSessionId);
      this.hostSessionId = undefined;
      this.modelInvoker.dispose();
    });
  }

  /** Runtime actions such as getAllTools() are unavailable during factory loading. */
  private initializeHostTools(ctx: ExtensionCtx): void {
    if (this.toolsInitialized) return;
    this.toolsInitialized = true;

    const toolInventory = this.pi.getAllTools?.();
    const nativeBash = findNativeTool(toolInventory, "bash");
    const nativeEval = findNativeTool(toolInventory, "eval");
    const nativeWrite = findNativeTool(toolInventory, "write");
    const sessionId = sessionIdOf(ctx);
    this.hostSessionId = sessionId;

    if (!toolInventory) {
      this.bashGate!.register(this.pi);
      this.coverage.bash = true;
      if (this.configStore.config.coverage.eval) {
        this.evalGate!.register(this.pi);
        this.coverage.eval = true;
      }
    } else if (nativeBash && nativeEval) {
      this.bashGate!.register(this.pi, nativeBash);
      this.coverage.bash = true;
      if (this.configStore.config.coverage.eval) {
        this.evalGate!.register(this.pi, nativeEval);
        this.coverage.eval = true;
      }
      // Proc stdin tracking needs both a public proc:// write target and a
      // stable session id for ownership/cleanup.
      this.procInputEnabled = nativeWrite !== undefined && sessionId !== undefined;
      this.coverage.procInput = this.procInputEnabled
        ? this.coverage.eval ? "tracked" : "shell-only"
        : "false";
    } else {
      this.eventGate.bash = toolInventory.some((tool) => tool.name === "bash");
      this.eventGate.eval =
        this.configStore.config.coverage.eval && toolInventory.some((tool) => tool.name === "eval");
      this.coverage.bash = this.eventGate.bash;
      this.coverage.eval = this.eventGate.eval;
      // Fallback hosts may still expose the public write tool and a stable
      // session id even when the native Bash/Eval wrappers are incomplete.
      this.procInputEnabled = nativeWrite !== undefined && sessionId !== undefined;
      this.coverage.procInput = this.procInputEnabled
        ? this.coverage.eval ? "tracked" : "shell-only"
        : "false";
    }

    this.coverage.protectedPaths =
      !toolInventory ||
      this.coverage.eval ||
      toolInventory.some((tool) => ["write", "edit", "apply_patch", "ast_edit"].includes(tool.name));
  }

  // ── slash command: /smart-approve [auto|interactive|status] ────────

  private handleCommand(args: unknown, ctx: ExtensionCtx): void {
    const arg = String(args ?? "").trim().toLowerCase();
    if (arg === "") {
      const next = this.modeManager.toggle();
      ctx.ui.notify?.(this.t.modeSwitched(next), "info");
    } else if (arg === "auto" || arg === "interactive") {
      const next = this.modeManager.set(arg);
      ctx.ui.notify?.(this.t.modeSwitched(next), "info");
    } else if (arg === "status") {
      ctx.ui.notify?.(this.modeManager.status(), "info");
    } else {
      ctx.ui.notify?.(this.t.cmdHelp, "info");
    }
    ctx.ui.setStatus("smart-approve-mode", this.configStore.config.mode);
  }


  // ── write/edit interception on protected paths ────────────────────

  private async handleProtectedPaths(
    event: ToolCallEvent,
    ctx: ExtensionCtx,
  ): Promise<void | { block: true; reason: string }> {
    const config = this.configStore.config;
    const cwd = ctx.cwd || process.cwd();
    const targets = collectProtectedTargets(event).filter(
      (target) => !/^(?:proc|xd|agent|out):\/\//i.test(target),
    );
    const hardBlockedPaths = targets.filter((target) => isHardBlockedFileTarget(target, cwd));
    if (hardBlockedPaths.length > 0) {
      const label = makeLabel(
        "System-sensitive file or device writes are hard-blocked",
        "系统敏感文件或设备写入已拦截",
      );
      return { block: true, reason: `${label[this.lang]}: ${hardBlockedPaths.join("\n")}` };
    }
    const protectedPaths = targets.filter((target) => this.pathMatcher.isProtected(target, cwd));
    if (protectedPaths.length === 0) return;

    const needsReview = config.rememberDecisions
      ? protectedPaths.filter((target) => !this.allowList.isAllowed(event.toolName, target, cwd))
      : protectedPaths;
    if (needsReview.length === 0) return;

    const targetLabel = needsReview.join("\n");
    const t = this.t;
    if (!ctx.hasUI) return { block: true, reason: t.blockedPathNoUI(targetLabel) };

    const titleTarget = needsReview.length === 1 ? needsReview[0] : `${needsReview.length} sensitive files`;
    const title = t.confirmPathTitle(titleTarget);
    const body = `${t.filePath}: ${targetLabel}\n\n${t.allowPrompt}`;
    const decision = await confirmWithRemember(ctx, title, body, t, config.rememberDecisions);
    if (!decision.ok) return { block: true, reason: t.userDenied(targetLabel) };

    if (decision.remember === "session") {
      for (const target of needsReview) this.allowList.rememberSession(event.toolName, target, cwd);
    } else if (decision.remember === "permanent") {
      for (const target of needsReview) this.allowList.rememberPermanent(event.toolName, target, cwd);
    }
  }
}

// Extension host expects a default export: (pi) => void, registering hooks.
export default function smartApprove(pi: ExtensionAPI): void {
  new SmartApprove(pi).register();
}
