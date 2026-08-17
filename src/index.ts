/**
 * Smart Approve — extension entry point.
 *
 * Orchestrator: wires the collaborators (config, allow-list, policy,
 * gates, mode manager, hub guard, LLM invoker) at construction and
 * registers:
 *
 *   - BashToolGate  — custom "bash" tool (shadows built-in, delegates)
 *   - EvalToolGate  — custom "eval" tool (same pattern, coverage.eval)
 *   - HubLaunchGuard — tool_call interception for hub op:"start"
 *   - write/edit protected-path interception (tool_call hook)
 *   - /smart-approve slash command (runtime mode switching)
 *
 * The custom-tool execute() path is NOT subject to
 * EXTENSION_HANDLER_TIMEOUT_MS (30s), so LLM analysis and dialogs have
 * no wall-clock pressure; the tool_call handlers are regex/path-only and
 * fit the 30s budget.
 */

import type { ExtensionAPI, ExtensionCtx, ToolCallEvent } from "./types";
import { Logger } from "./logger";
import { detectLang, getI18n } from "./i18n";
import type { Lang } from "./i18n";
import { ProtectedPathMatcher } from "./paths";
import { ConfigStore } from "./config";
import { AllowList } from "./allowlist";
import { SessionContextGatherer } from "./context";
import { HostResolver, ModelInvoker } from "./host";
import { AutoDecisionPolicy } from "./policy";
import { ModeManager } from "./mode-manager";
import { BashToolGate } from "./bash-tool";
import { EvalToolGate } from "./eval-tool";
import { HubLaunchGuard } from "./hub-guard.ts";
import { confirmWithRemember } from "./dialog";

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
  private readonly modeManager: ModeManager;
  private readonly hubGuard: HubLaunchGuard;

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
    this.hubGuard = new HubLaunchGuard();
    this.modeManager = new ModeManager(this.configStore, this.logger, {
      eval: this.configStore.config.coverage.eval,
      hub: true,
    });
  }

  /** Register the shadowed tools, event hooks and slash command. */
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
    };

    // Custom "bash" tool: shadows the built-in; execute() is free of the
    // 30s handler timeout, so LLM analysis + dialogs have no pressure.
    new BashToolGate(shared).register(this.pi);

    // Custom "eval" tool (opt-out via coverage.eval=false).
    if (this.configStore.config.coverage.eval) {
      new EvalToolGate(shared).register(this.pi);
    }

    // tool_call interception: protected paths (write/edit) + hub launches.
    this.pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionCtx) => {
      if (event.toolName === "write" || event.toolName === "edit") {
        return this.handleWrite(event, ctx);
      }
      if (event.toolName === "hub") {
        return this.handleHub(event, ctx);
      }
    });

    // Persistent mode chip in the TUI status bar.
    this.pi.on("session_start", async (_event, ctx: ExtensionCtx) => {
      ctx.ui.setStatus("smart-approve-mode", this.configStore.config.mode);
    });

    // Runtime mode switching via slash command.
    this.pi.registerCommand("smart-approve", {
      description: "Toggle or inspect smart-approve mode (auto/interactive)",
      handler: async (args: unknown, ctx: ExtensionCtx) => {
        this.handleCommand(args, ctx);
      },
    });

    this.pi.on("session_shutdown", async () => {
      // Kill the persistent RPC model child so it does not outlive the session.
      this.modelInvoker.dispose();
    });
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

  // ── hub launch interception (regex gate, no LLM) ───────────────────

  private async handleHub(
    event: ToolCallEvent,
    ctx: ExtensionCtx,
  ): Promise<void | { block: true; reason: string }> {
    const verdict = this.hubGuard.evaluate(
      {
        op: event.input.op,
        application: event.input.application,
        args: event.input.args,
        cwd: event.input.cwd,
      },
      ctx.cwd || process.cwd(),
    );
    if (!verdict.block || !verdict.reason) return;
    const reason = this.lang === "zh" ? verdict.reason.zh : verdict.reason.en;
    this.logger.log(`hub-guard: blocked — ${reason}`);
    return { block: true, reason };
  }

  // ── write/edit interception on protected paths ────────────────────

  private async handleWrite(
    event: ToolCallEvent,
    ctx: ExtensionCtx,
  ): Promise<void | { block: true; reason: string }> {
    const config = this.configStore.config;
    if (config.protectedPaths.length === 0) return;

    const filePath = event.input?.path ?? "";
    if (!filePath) return;
    const cwd = ctx.cwd || process.cwd();
    const t = this.t;

    // Protected check FIRST — non-protected paths never consult the
    // allowlist (mirrors the gate chain: hard-block before allowlist).
    if (!this.pathMatcher.isProtected(filePath)) return;

    if (config.rememberDecisions && this.allowList.isAllowed(event.toolName, filePath, cwd)) {
      return;
    }

    if (!ctx.hasUI) {
      return { block: true, reason: t.blockedPathNoUI(filePath) };
    }

    const title = t.confirmPathTitle(filePath);
    const body = `${t.filePath}: ${filePath}\n\n${t.allowPrompt}`;

    const decision = await confirmWithRemember(ctx, title, body, t, config.rememberDecisions);
    if (!decision.ok) {
      return { block: true, reason: t.userDenied(filePath) };
    }

    if (decision.remember === "session") {
      this.allowList.rememberSession(event.toolName, filePath, cwd);
    } else if (decision.remember === "permanent") {
      this.allowList.rememberPermanent(event.toolName, filePath, cwd);
    }
  }
}

// Extension host expects a default export: (pi) => void, registering hooks.
export default function smartApprove(pi: ExtensionAPI): void {
  new SmartApprove(pi).register();
}
