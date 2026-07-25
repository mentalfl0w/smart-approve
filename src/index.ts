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

  /**
   * Best-effort late-arrival notifier.  When the LLM race loses (model slower
   * than llmRaceMs), the dialog is shown immediately with rule-based labels;
   * this attaches a continuation that surfaces the model result via ui.notify
   * whenever it eventually resolves.
   *
   * Runs as a detached promise — the callback body is wrapped in try/catch
   * because OMP treats unhandled throws in detached callbacks as fatal
   * (session teardown).  ctx validity after handler return is undocumented,
   * so every ctx touch is guarded.
   */
  private scheduleLateNotify(
    ctx: ExtensionCtx,
    llmPromise: Promise<{ risk?: string; summary?: string } | null>,
    t: { analysisLate: (risk: string, summary: string) => string },
  ): void {
    llmPromise
      .then((late) => {
        try {
          if (late) {
            const risk = late.risk ?? "?";
            const summary = late.summary ?? "";
            ctx.ui.notify?.(t.analysisLate(risk, summary), "info");
          }
        } catch {
          // ctx may be stale after handler return; swallow — decorative-only.
        }
      })
      .catch(() => void 0);
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

      // Race: start the LLM, but show the dialog immediately if it doesn't
      // return within llmRaceMs. Late-arriving results are surfaced via
      // ui.notify so the user is never blocked waiting for the model.
      const llmPromise = this.modelInvoker
        .analyze(this.pi, cmd, behaviorLabels, contextSection, t, config.model, config.llmTimeoutMs)
        .catch(() => null);
      const raceResult = await Promise.race([
        llmPromise,
        new Promise<null>((resolve) => setTimeout(() => resolve(null), config.llmRaceMs)),
      ]);
      analysisText = formatAnalysis(raceResult, t);
      this.logger.log(`analyzeRisk: analysisText=${analysisText ? "OK" : "null (will notify if late)"}`);
      ctx.ui.setStatus("smart-approve", "");

      // If the race lost, surface the LLM result via notify when it arrives.
      if (!analysisText) {
        this.scheduleLateNotify(ctx, llmPromise, t);
      }
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
      const llmPromise = this.modelInvoker
        .invoke(this.pi, filePrompt, config.model, config.llmTimeoutMs)
        .catch(() => null);
      const raceResult = await Promise.race([
        llmPromise,
        new Promise<null>((resolve) => setTimeout(() => resolve(null), config.llmRaceMs)),
      ]);
      analysisText = formatAnalysis(raceResult, t);
      ctx.ui.setStatus("smart-approve", "");

      if (!analysisText) {
        this.scheduleLateNotify(ctx, llmPromise, t);
      }
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

