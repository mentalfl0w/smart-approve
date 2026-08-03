/**
 * Smart Approve — extension entry point.
 *
 * Registers a custom "bash" tool that replaces OMP's built-in bash,
 * moving dangerous-command approval into execute() which is NOT subject
 * to EXTENSION_HANDLER_TIMEOUT_MS (30s). This removes all time pressure
 * from LLM risk analysis and the approval dialog.
 *
 * Also intercepts write/edit to protected paths via the tool_call hook
 * (the 30s budget is sufficient for path matching + confirmation dialog).
 *
 * Setup:
 *   config.yml: bash.enabled: false  (removes built-in bash tool)
 *   config.yml: tools.approvalMode: yolo
 *   smart-approve.json: llmAnalysis, model, ...
 *
 * Configuration: ~/.omp/agent/smart-approve.json (or ~/.pi/agent/... on pi)
 * Allow-list:     ~/.omp/agent/smart-approve-allow.json
 *
 * Module layout:
 *   types.ts     — shared interfaces (ExtensionAPI, ToolDefinition, etc.)
 *   logger.ts    — Logger (file + stderr)
 *   i18n.ts      — locale detection + bilingual strings
 *   behaviors.ts — behavior catalog, git parser, composite analysis
 *   paths.ts     — ProtectedPathMatcher
 *   config.ts    — ConfigStore
 *   allowlist.ts — AllowList
 *   context.ts   — SessionContextGatherer
 *   host.ts      — HostResolver + ModelInvoker
 *   dialog.ts    — confirmWithRemember + formatAnalysis
 *   bash-tool.ts — custom "bash" tool (replaces built-in)
 *   index.ts     — SmartApprove orchestrator (this file)
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
import { confirmWithRemember } from "./dialog";
import { registerBashTool } from "./bash-tool";

/**
 * Smart Approve extension orchestrator.
 *
 * Wires the collaborators (config, allow-list, matcher, LLM invoker) at
 * construction and routes tool_call events through the two interception
 * pipelines (bash + protected-path).  The orchestration is intentionally
 * thin: each concern lives in its own class.
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

  constructor(private readonly pi: ExtensionAPI) {
    this.logger = new Logger();
    this.lang = detectLang();
    this.configStore = new ConfigStore(this.logger);
    this.allowList = new AllowList(this.configStore.allowListPath, this.logger);
    this.pathMatcher = new ProtectedPathMatcher(this.configStore.config.protectedPaths);
    this.contextGatherer = new SessionContextGatherer(this.logger);
    const host = new HostResolver(this.logger);
    this.modelInvoker = new ModelInvoker(host, this.logger, this.configStore.config.analysisTimeoutMs);
  }

  /** Register the custom bash tool + write/edit hook. No-op if disabled. */
  register(): void {
    if (!this.configStore.config.enabled) return;

    // Register the custom "bash" tool (replaces built-in bash).
    // execute() is NOT subject to EXTENSION_HANDLER_TIMEOUT_MS (30s),
    // so LLM analysis and the approval dialog have no time pressure.
    registerBashTool(this.pi, {
      config: this.configStore.config,
      allowList: this.allowList,
      contextGatherer: this.contextGatherer,
      modelInvoker: this.modelInvoker,
      logger: this.logger,
      lang: this.lang,
      t: this.t,
    });

    // Intercept write/edit on protected paths (30s budget is sufficient
    // for path matching + confirmation dialog).
    this.pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionCtx) => {
      if (event.toolName === "write" || event.toolName === "edit") {
        return this.handleWrite(event, ctx);
      }
    });

    this.pi.on("session_shutdown", async () => {
      // Kill the persistent RPC model child so it does not outlive the session.
      this.modelInvoker.dispose();
    });
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
    // allowlist (mirrors the bash chain: hard-block before allowlist).
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

