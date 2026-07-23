/**
 * Smart Approve — hook entry point.
 *
 * Intercepts dangerous bash commands AND write/edit to sensitive paths.
 * Uses behavior-based detection (not just regex) and feeds session context
 * to the LLM reviewer. Remembers decisions (session + permanent).
 *
 * Setup: tools.approvalMode: yolo (auto-approve all) + this hook intercepts
 * dangerous commands. Safe commands pass through with zero interruption.
 * When a dangerous pattern/behavior matches, the hook invokes the smol model
 * via the host's one-shot print mode (`omp -p` or `pi -p`) to analyze the
 * command with full session context, then shows a confirmation dialog.
 *
 * Output language adapts to the user's locale (zh / en).
 *
 * Configuration: ~/.omp/agent/smart-approve.json (or ~/.pi/agent/... on pi)
 * Allow-list:     ~/.omp/agent/smart-approve-allow.json
 *
 * Module layout:
 *   types.ts    — shared interfaces
 *   logger.ts   — Logger (file + stderr)
 *   i18n.ts     — locale detection + bilingual strings
 *   behaviors.ts — behavior catalog, git parser, composite analysis
 *   paths.ts    — ProtectedPathMatcher
 *   config.ts   — ConfigStore
 *   allowlist.ts — AllowList
 *   context.ts  — SessionContextGatherer
 *   host.ts     — HostResolver + ModelInvoker
 *   dialog.ts   — confirmWithRemember + formatAnalysis
 *   index.ts    — SmartApprove orchestrator (this file)
 */

import type { ExtensionAPI, ExtensionCtx, ToolCallEvent } from "./types";
import { Logger } from "./logger";
import { detectLang, getI18n } from "./i18n";
import type { Lang } from "./i18n";
import { analyzeCommand } from "./behaviors";
import { ProtectedPathMatcher } from "./paths";
import { ConfigStore } from "./config";
import { AllowList } from "./allowlist";
import { SessionContextGatherer } from "./context";
import { HostResolver, ModelInvoker } from "./host";
import { confirmWithRemember, formatAnalysis } from "./dialog";

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
    this.modelInvoker = new ModelInvoker(host, this.logger);
  }

  /** Register the tool_call hook.  No-op if the extension is disabled. */
  register(): void {
    if (!this.configStore.config.enabled) return;

    this.pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionCtx) => {
      if (event.toolName === "bash") {
        return this.handleBash(event, ctx);
      }
      if (event.toolName === "write" || event.toolName === "edit") {
        return this.handleWrite(event, ctx);
      }
    });

    this.pi.on("session_shutdown", async () => {
      // Status is session-scoped; no cleanup needed
    });
  }

  // ── bash interception ──────────────────────────────────────────────

  private async handleBash(
    event: ToolCallEvent,
    ctx: ExtensionCtx,
  ): Promise<void | { block: true; reason: string }> {
    const cmd = event.input?.command ?? "";
    if (!cmd.trim()) return;
    const cwd = ctx.cwd || process.cwd();
    const config = this.configStore.config;
    const t = this.t;

    if (config.rememberDecisions && this.allowList.isAllowed("bash", cmd, cwd)) {
      return; // remembered allow — pass through
    }

    const analysis = analyzeCommand(cmd);
    if (analysis.behaviors.length === 0) return; // safe command, pass through

    const label = analysis.labels[0]?.[this.lang] || analysis.labels[0]?.en || "danger";

    if (analysis.hardBlocked) {
      return { block: true, reason: t.blockedNoUI(label) + "\n" + t.command + ": " + cmd };
    }
    if (!ctx.hasUI) {
      return { block: true, reason: t.blockedNoUI(label) + "\n" + t.command + ": " + cmd };
    }

    let analysisText: string | null = null;
    if (config.llmAnalysis) {
      ctx.ui.setStatus("smart-approve", t.analyzing);
      const sessionCtx = this.contextGatherer.gather(ctx, config.contextMaxChars);
      const contextSection = this.contextGatherer.format(sessionCtx, t);
      const behaviorLabels = analysis.labels.map((l) => l[this.lang] || l.en);
      this.logger.log(`analyzeRisk: cmd="${cmd.slice(0, 80)}" behaviors=[${behaviorLabels.join(",")}]`);
      const llmResult = await this.modelInvoker.analyze(this.pi, cmd, behaviorLabels, contextSection, t);
      analysisText = formatAnalysis(llmResult, t);
      this.logger.log(`analyzeRisk: analysisText=${analysisText ? "OK" : "null"}`);
      ctx.ui.setStatus("smart-approve", "");
    }

    const title = t.confirmTitle(label);
    const body = analysisText
      ? `${analysisText}\n\n────────\n${t.command}: ${cmd}\n\n${t.allowPrompt}`
      : `${t.analysisUnavailable}\n\n${t.command}: ${cmd}\n\n${t.allowPrompt}`;

    const decision = await confirmWithRemember(ctx, title, body, t, config.rememberDecisions);
    if (!decision.ok) {
      return { block: true, reason: t.userDenied(label) };
    }

    if (decision.remember === "session") {
      this.allowList.rememberSession("bash", cmd, cwd);
    } else if (decision.remember === "permanent") {
      this.allowList.rememberPermanent("bash", cmd, cwd);
    }
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

    if (config.rememberDecisions && this.allowList.isAllowed(event.toolName, filePath, cwd)) {
      return;
    }
    if (!this.pathMatcher.isProtected(filePath)) return;

    if (!ctx.hasUI) {
      return { block: true, reason: t.blockedPathNoUI(filePath) };
    }

    let analysisText: string | null = null;
    if (config.llmAnalysis) {
      ctx.ui.setStatus("smart-approve", t.analyzing);
      const sessionCtx = this.contextGatherer.gather(ctx, config.contextMaxChars);
      const filePrompt = [
        t.promptIntro,
        "",
        `=== ${t.promptContext} ===`,
        this.contextGatherer.format(sessionCtx, t),
        `=== ${t.promptRule} ===`,
        `${event.toolName} on protected path: ${filePath}`,
        "",
        `=== ${t.promptCommand} ===`,
        `${event.toolName} ${filePath}`,
        "",
        t.promptOutput,
        '- risk: "low" | "medium" | "high"',
        `- summary: ${t.promptSummaryDesc}`,
        `- detail: ${t.promptDetailDesc}`,
        `- recommend: ${t.promptRecommendDesc}`,
        "",
        t.promptOnlyJson,
      ].join("\n");

      this.logger.log(`analyzeRisk(write): tool=${event.toolName} path=${filePath}`);
      const llmResult = await this.modelInvoker.invoke(this.pi, filePrompt);
      analysisText = formatAnalysis(llmResult, t);
      ctx.ui.setStatus("smart-approve", "");
    }

    const title = t.confirmPathTitle(filePath);
    const body = analysisText
      ? `${analysisText}\n\n────────\n${t.filePath}: ${filePath}\n\n${t.allowPrompt}`
      : `${t.analysisUnavailable}\n\n${t.filePath}: ${filePath}\n\n${t.allowPrompt}`;

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

