/**
 * Smart Approve — shared approval decision flow.
 *
 * One flow for every covered entry point (Bash, Eval, protected-path file
 * tools, and proc stdin routed through a gate):
 *
 *   allow-list -> hard pre-model blocks for UI-less hosts -> model analysis
 *   -> auto verdict by threshold, or interactive dialog -> remember.
 *
 * The flow never treats "statically undeterminable" as a decision by itself:
 * dynamic paths, MCP dispatch, and protected files all reach the model (or
 * the user) instead of being auto-approved by a regex fallback.
 */

import type { AgentToolResult, ExtensionCtx, RememberChoice, RiskAnalysis } from "./types";
import type { SmartApproveConfig } from "./config";
import type { AutoDecisionPolicy, PolicyDecision } from "./policy";
import type { LoggerLike } from "./logger";
import type { I18n, Lang } from "./i18n";
import { confirmWithRemember, formatAnalysis } from "./dialog";

/** Narrow collaborator contracts (dependency inversion): concrete classes
 *  satisfy these structurally; tests can supply stubs. */
export interface AllowListLike {
  isAllowed(tool: string, content: string, cwd: string): boolean;
  rememberSession(tool: string, content: string, cwd: string): void;
  rememberPermanent(tool: string, content: string, cwd: string): void;
}

export interface ContextGathererLike {
  gather(ctx: ExtensionCtx, maxChars: number): unknown;
  format(sessionCtx: unknown, t: I18n): string;
}

export interface ModelInvokerLike {
  analyze(
    subject: string,
    subjectLabel: string,
    behaviorLabels: string[],
    contextSection: string,
    t: I18n,
    model: string,
    signal?: AbortSignal,
    ctx?: ExtensionCtx,
  ): Promise<RiskAnalysis | null>;
}

export interface ApprovalDeps {
  config: SmartApproveConfig;
  allowList: AllowListLike;
  contextGatherer: ContextGathererLike;
  modelInvoker: ModelInvokerLike;
  policy: AutoDecisionPolicy;
  logger: LoggerLike;
  lang: Lang;
  t: I18n;
}

/** One reviewable operation.  `displaySubject` is what the user may see;
 *  `promptSubject` is the exact evidence handed to the model. */
export interface ApprovalRequest {
  toolName: string;
  /** Localized primary label, used in titles and decision reasons. */
  label: string;
  /** Localized subject label ("Command", "Code", "File"). */
  subjectLabel: string;
  /** Subject used by the model prompt. */
  promptSubject: string;
  promptSubjectLabel: string;
  /** Subject rendered in the confirmation dialog and block text. */
  displaySubject: string;
  behaviorLabels: string[];
  /** Allow-list key.  null means this operation cannot be safely keyed for
   *  remembered decisions (e.g. its working directory is runtime-defined),
   *  so no memory option is offered. */
  memoryKey: string | null;
  cwd: string;
  rememberScope: "session" | "both";
  /** Overrides the default "Dangerous command" dialog title. */
  title?: string;
  /** Persists a remembered decision for multi-target reviews.  When omitted,
   *  the flow writes the single memoryKey through the allow-list. */
  remember?: (choice: Exclude<RememberChoice, "none">) => void;
}

export type ApprovalSource =
  | "allowlist"
  | "model"
  | "user"
  | "no-ui"
  | "no-verdict"
  | "aborted";

export type ApprovalOutcome =
  | { allowed: true; source: "allowlist" | "model" | "user" }
  | { allowed: false; source: ApprovalSource; result: AgentToolResult };

/** Per-context in-flight analysis count so parallel calls do not clear each
 *  other's status indicator. */
const activeAnalyses = new WeakMap<object, number>();

function beginAnalysisStatus(ctx: ExtensionCtx, text: string): void {
  const active = (activeAnalyses.get(ctx) ?? 0) + 1;
  activeAnalyses.set(ctx, active);
  ctx.ui.setStatus("smart-approve", text);
}

function endAnalysisStatus(ctx: ExtensionCtx): void {
  const active = Math.max(0, (activeAnalyses.get(ctx) ?? 1) - 1);
  if (active === 0) {
    activeAnalyses.delete(ctx);
    ctx.ui.setStatus("smart-approve", undefined);
  } else {
    activeAnalyses.set(ctx, active);
  }
}

/**
 * Shared decision flow.  Stateless per call; collaborators are injected so
 * parallel calls cannot share per-request analysis state.
 */
export class ApprovalFlow {
  constructor(private readonly deps: ApprovalDeps) {}

  async decide(
    request: ApprovalRequest,
    ctx: ExtensionCtx,
    signal?: AbortSignal,
  ): Promise<ApprovalOutcome> {
    const { config, allowList, logger, t } = this.deps;

    if (signal?.aborted) return this.aborted();

    // Remembered decisions are human decisions; hard blocks are checked by
    // the caller before this flow runs and therefore always win.
    if (config.rememberDecisions && request.memoryKey !== null) {
      if (allowList.isAllowed(request.toolName, request.memoryKey, request.cwd)) {
        logger.log(`${request.toolName}: remembered decision allows review`);
        return { allowed: true, source: "allowlist" };
      }
    }

    const hasUI = ctx.hasUI === true;
    const autoMode = config.mode === "auto";

    // No UI means no human can confirm.  Interactive always blocks; auto
    // blocks too unless autoInHeadless explicitly enables headless verdicts.
    if (!hasUI && !autoMode) {
      logger.log(`${request.toolName}: blocked (no UI, interactive mode) — ${request.label}`);
      return this.block(request, "no-ui", t.blockedNoUI, t.decisionSourceNoUI);
    }
    if (!hasUI && autoMode && !config.autoInHeadless) {
      logger.log(`${request.toolName}: blocked (no UI, autoInHeadless=false) — ${request.label}`);
      return this.block(request, "no-ui", t.blockedNoUI, t.decisionSourceAutoHeadless);
    }

    const analysis = await this.analyze(request, ctx, signal);
    if (signal?.aborted) return this.aborted();

    const decision = this.deps.policy.decide(analysis);
    if (decision) {
      logger.log(
        `${request.toolName}: model verdict=${decision.verdict} reason=${decision.reason} — ${request.label}`,
      );
    } else {
      logger.log(
        `${request.toolName}: no usable model verdict (${config.llmAnalysis ? "analysis failed" : "analysis disabled"}) — ${request.label}`,
      );
    }

    if (autoMode) {
      if (decision) {
        return this.applyAutoDecision(request, decision, analysis, ctx);
      }
      if (!hasUI) {
        logger.log(`${request.toolName}: blocked (no verdict, no UI) — ${request.label}`);
        return this.block(
          request,
          "no-verdict",
          t.blockedNoVerdictNoUI,
          t.decisionSourceNoVerdictNoUI,
        );
      }
      logger.log(`${request.toolName}: no verdict, asking user — ${request.label}`);
    }

    return this.askUser(request, analysis, decision, ctx, signal);
  }

  /** Run the configured model.  Failures are logged and become "no verdict";
   *  they never auto-allow. */
  private async analyze(
    request: ApprovalRequest,
    ctx: ExtensionCtx,
    signal?: AbortSignal,
  ): Promise<RiskAnalysis | null> {
    const { config, contextGatherer, modelInvoker, logger, t } = this.deps;
    if (!config.llmAnalysis) return null;

    beginAnalysisStatus(ctx, t.analyzing);
    try {
      const sessionCtx = contextGatherer.gather(ctx, config.contextMaxChars);
      const contextSection = contextGatherer.format(sessionCtx, t);
      logger.log(
        `${request.toolName}: analyzeRisk subject="${request.promptSubject.slice(0, 80)}" behaviors=[${request.behaviorLabels.join(",")}]`,
      );
      return await modelInvoker.analyze(
        request.promptSubject,
        request.promptSubjectLabel,
        request.behaviorLabels,
        contextSection,
        t,
        config.model,
        signal,
        ctx,
      );
    } catch (e) {
      logger.log(
        `${request.toolName}: LLM analysis failed: ${e instanceof Error ? e.message : String(e)}`,
      );
      return null;
    } finally {
      endAnalysisStatus(ctx);
    }
  }

  private applyAutoDecision(
    request: ApprovalRequest,
    decision: PolicyDecision,
    analysis: RiskAnalysis | null,
    ctx: ExtensionCtx,
  ): ApprovalOutcome {
    const { logger, t } = this.deps;
    const detail = modelDetail(analysis);
    logger.log(
      `${request.toolName}: auto decision=${decision.verdict} reason=${decision.reason} (${request.label})`,
    );
    if (decision.verdict === "allow") {
      ctx.ui.notify?.(t.autoAllowedByModel(request.label, detail), "info");
      return { allowed: true, source: "model" };
    }
    ctx.ui.notify?.(t.autoBlockedByModel(request.label, detail), "warning");
    return {
      allowed: false,
      source: "model",
      result: this.error(
        `${t.autoBlockedByModel(request.label, detail)}\n${request.subjectLabel}: ${request.displaySubject}`,
        { blocked: true, reason: "auto" },
      ),
    };
  }

  private async askUser(
    request: ApprovalRequest,
    analysis: RiskAnalysis | null,
    decision: PolicyDecision | null,
    ctx: ExtensionCtx,
    signal?: AbortSignal,
  ): Promise<ApprovalOutcome> {
    const { config, allowList, logger, t } = this.deps;
    const analysisText = formatAnalysis(analysis, t);
    const sourceLine = analysisText
      ? t.decisionSourceModel(modelDetail(analysis))
      : config.llmAnalysis
        ? t.decisionSourceNoVerdict
        : t.decisionSourceAnalysisDisabled;
    const body = [
      analysisText ?? (config.llmAnalysis ? t.analysisUnavailable : t.analysisDisabled),
      "",
      sourceLine,
      "",
      `${t.promptRule}: ${request.behaviorLabels.join("; ") || request.label}`,
      `${request.subjectLabel}: ${request.displaySubject}`,
      "",
      t.allowPrompt,
    ].join("\n");

    const remember = config.rememberDecisions &&
      (request.memoryKey !== null || request.remember !== undefined);
    const outcome = await confirmWithRemember(
      ctx,
      request.title ?? t.confirmTitle(request.label),
      body,
      t,
      remember,
      request.rememberScope,
    );
    if (!outcome.ok) {
      logger.log(`${request.toolName}: user denied — ${request.label}`);
      return {
        allowed: false,
        source: "user",
        result: this.error(t.userDenied(request.label), {
          denied: true,
          reason: request.label,
          source: "user",
        }),
      };
    }

    // The host can abort the tool call while the dialog is open, and the
    // pending prompt may still resolve with an allow afterwards.  A cancelled
    // call must neither execute nor record a remembered decision.
    if (signal?.aborted) {
      logger.log(`${request.toolName}: aborted after approval dialog, not executing — ${request.label}`);
      return this.aborted();
    }

    if (outcome.remember === "session") {
      if (request.remember) request.remember("session");
      else if (request.memoryKey !== null) {
        allowList.rememberSession(request.toolName, request.memoryKey, request.cwd);
      }
    } else if (outcome.remember === "permanent") {
      if (request.remember) request.remember("permanent");
      else if (request.memoryKey !== null) {
        allowList.rememberPermanent(request.toolName, request.memoryKey, request.cwd);
      }
    }

    logger.log(
      `${request.toolName}: user allowed (remember=${outcome.remember}, model=${decision ? "verdict" : "no-verdict"})`,
    );
    return { allowed: true, source: "user" };
  }

  private block(
    request: ApprovalRequest,
    source: ApprovalSource,
    reasonText: (label: string) => string,
    sourceText: string,
  ): ApprovalOutcome {
    return {
      allowed: false,
      source,
      result: this.error(
        `${reasonText(request.label)}\n${sourceText}\n${request.subjectLabel}: ${request.displaySubject}`,
        { blocked: true, reason: source },
      ),
    };
  }

  private aborted(): ApprovalOutcome {
    return {
      allowed: false,
      source: "aborted",
      result: { content: [{ type: "text", text: "(aborted)" }], details: { aborted: true } },
    };
  }

  private error(text: string, details: Record<string, unknown>): AgentToolResult {
    return { content: [{ type: "text", text }], details, isError: true };
  }
}

/** A compact, user-visible fingerprint of the model verdict. */
export function modelDetail(analysis: RiskAnalysis | null): string {
  const risk = analysis?.risk?.trim();
  const recommend = analysis?.recommend?.trim();
  return `risk=${risk || "unknown"}, recommend=${recommend || "unknown"}`;
}
