/**
 * Smart Approve — shared approval gate (template method).
 *
 * ToolGate owns the decision pipeline that was previously bash-only:
 *
 *   hard-block -> allowlist -> no-behavior -> headless check
 *   -> LLM analysis -> verdict (auto policy or interactive dialog)
 *   -> remember -> delegate
 *
 * Concrete gates (bash, eval) supply the three tool-specific hooks:
 * analyze() / buildKey() / delegate(), plus the schema and subject
 * extraction.  The flow itself never varies, so every covered tool gets
 * identical approval semantics.
 */

import type {
  ExtensionAPI,
  ExtensionCtx,
  AgentToolResult,
  DangerAnalysis,
  RiskAnalysis,
  ZodLike,
} from "./types";
import type { SmartApproveConfig } from "./config";
import type { AutoDecisionPolicy } from "./policy";
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
  ): Promise<RiskAnalysis | null>;
}


/** Shared collaborators injected into every gate instance. */
export interface GateDeps {
  config: SmartApproveConfig;
  allowList: AllowListLike;
  contextGatherer: ContextGathererLike;
  modelInvoker: ModelInvokerLike;
  policy: AutoDecisionPolicy;
  logger: LoggerLike;
  lang: Lang;
  t: I18n;
}

/** Tool update callback, matching ToolDefinition.execute's onUpdate. */
export type ToolUpdateCallback =
  ((update: { content: unknown[]; details?: unknown }) => void) | undefined;

export abstract class ToolGate {
  // Public so concrete gates can be constructed by the orchestrator and
  // tests; the class is abstract, so it cannot be instantiated directly.
  constructor(protected readonly deps: GateDeps) {}

  // ── Tool identity (per concrete gate) ──────────────────────────────

  /** Tool name; must shadow a native built-in for delegation to work. */
  abstract readonly toolName: string;
  protected abstract readonly toolLabel: string;
  protected abstract readonly toolDescription: string;
  /** Mirrors the native tool's strict flag (undefined = not set). */
  protected get strict(): boolean | undefined { return undefined; }
  /** "both" = session+permanent remember; "session" = session only. */
  protected abstract readonly rememberScope: "session" | "both";

  // ── Tool-specific hooks (per concrete gate) ────────────────────────

  /** zod schema builder (the host-injected zod is passed in). */
  protected abstract buildSchema(z: ZodLike): unknown;
  /** Extract the analyzable subject string from raw tool params. */
  protected abstract extractSubject(params: unknown): string;
  /** Working directory used for allowlist scoping. */
  protected abstract resolveCwd(params: unknown, ctx: ExtensionCtx): string;
  /** Per-tool behavior analysis. */
  protected abstract analyze(subject: string): DangerAnalysis;
  /** Allowlist key derived from the subject. */
  protected abstract buildKey(subject: string): string;
  /** Display label for the subject ("Command" / "Code"). */
  protected abstract subjectDisplayLabel(): string;
  /** LLM prompt section label for the subject. */
  protected abstract promptSubjectLabel(): string;
  /** Run the native tool with the original params. */
  protected abstract delegate(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult>;
  /** Empty-subject path; default passes through to the native tool. */
  protected onEmpty(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    return this.delegate(params, signal, onUpdate, ctx);
  }

  // ── Registration ───────────────────────────────────────────────────

  /** Register this gate as a custom tool shadowing the native built-in. */
  register(pi: ExtensionAPI): void {
    pi.registerTool({
      name: this.toolName,
      label: this.toolLabel,
      description: this.toolDescription,
      parameters: this.buildSchema(pi.zod),
      approval: "exec",
      strict: this.strict,
      execute: (toolCallId, params, signal, onUpdate, ctx) =>
        this.execute(params, signal, onUpdate, ctx),
    });
  }

  // ── Template method: the shared decision pipeline ──────────────────

  async execute(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    const { config, allowList, contextGatherer, modelInvoker, policy, logger, lang, t } = this.deps;

    const subject = this.extractSubject(params);
    if (!subject.trim()) {
      logger.log(`${this.toolName}: empty subject, passing through`);
      return this.onEmpty(params, signal, onUpdate, ctx);
    }

    const effectiveCwd = this.resolveCwd(params, ctx);
    const hasUI = ctx.hasUI;
    logger.log(`${this.toolName}: subject="${subject.slice(0, 80)}" cwd=${effectiveCwd} hasUI=${hasUI}`);

    const analysis = this.analyze(subject);
    const label = analysis.labels[0]?.[lang] || analysis.labels[0]?.en || "danger";
    const subjectLabel = this.subjectDisplayLabel();

    // 1. Hard-block wins over the allowlist (entries can predate a rule
    //    upgrade or be hand-edited into the allow file).
    if (analysis.hardBlocked) {
      logger.log(`${this.toolName}: hard-blocked (${label})`);
      return this.textError(`Blocked: ${label}\n${subjectLabel}: ${subject}`, { blocked: true, reason: label });
    }

    // 2. Allowlist hit → delegate directly.
    if (config.rememberDecisions && allowList.isAllowed(this.toolName, this.buildKey(subject), effectiveCwd)) {
      logger.log(`${this.toolName}: allowlist hit, delegating to native`);
      return this.delegate(params, signal, onUpdate, ctx);
    }

    // 3. No dangerous behavior → delegate directly (zero interruption).
    if (analysis.behaviors.length === 0) {
      return this.delegate(params, signal, onUpdate, ctx);
    }

    // 4. Dangerous but reviewable.  Headless contexts block unless auto
    //    mode is configured to decide by AI.
    const autoMode = config.mode === "auto";
    if (!hasUI && !(autoMode && config.autoInHeadless)) {
      logger.log(`${this.toolName}: blocked (no UI) — ${label}`);
      return this.textError(`${t.blockedNoUI(label)}\n${subjectLabel}: ${subject}`, { blocked: true, reason: "no-ui" });
    }

    // 5. LLM risk analysis (optional; inside execute(), free of the 30s
    //    EXTENSION_HANDLER_TIMEOUT_MS handler budget).
    let aiResult: RiskAnalysis | null = null;
    let analysisText: string | null = null;
    if (config.llmAnalysis) {
      ctx.ui.setStatus("smart-approve", t.analyzing);
      try {
        const sessionCtx = contextGatherer.gather(ctx, config.contextMaxChars);
        const contextSection = contextGatherer.format(sessionCtx, t);
        const behaviorLabels = analysis.labels.map((l) => l[lang] || l.en);
        logger.log(`${this.toolName}: analyzeRisk subject="${subject.slice(0, 80)}" behaviors=[${behaviorLabels.join(",")}]`);
        aiResult = await modelInvoker.analyze(
          subject, this.promptSubjectLabel(), behaviorLabels, contextSection, t, config.model, signal,
        );
        analysisText = formatAnalysis(aiResult, t);
        logger.log(`${this.toolName}: analysisText=${analysisText ? "OK" : "null"}`);
      } catch (e) {
        logger.log(`${this.toolName}: LLM analysis failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        ctx.ui.setStatus("smart-approve", undefined);
      }
    }

    // 5b. Interrupted while analyzing → abort, no decision.
    if (signal?.aborted) {
      logger.log(`${this.toolName}: aborted during analysis`);
      return { content: [{ type: "text", text: "(aborted)" }], details: { aborted: true } };
    }

    // 6. Verdict: auto mode → policy; interactive → dialog.
    if (autoMode) {
      const decision = policy.decide(aiResult, analysis.denyTier);
      logger.log(`${this.toolName}: auto decision=${decision.verdict} reason=${decision.reason} (${label})`);
      if (decision.verdict === "allow") {
        ctx.ui.notify?.(t.autoAllowed(label), "info");
        return this.delegate(params, signal, onUpdate, ctx);
      }
      ctx.ui.notify?.(t.autoBlocked(label), "warning");
      return this.textError(`${t.autoBlocked(label)}\n${subjectLabel}: ${subject}`, { blocked: true, reason: "auto" });
    }

    const title = t.confirmTitle(label);
    const body = analysisText
      ? `${analysisText}\n\n────────\n${subjectLabel}: ${subject}\n\n${t.allowPrompt}`
      : `${t.analysisUnavailable}\n\n${subjectLabel}: ${subject}\n\n${t.allowPrompt}`;

    const decision = await confirmWithRemember(ctx, title, body, t, config.rememberDecisions, this.rememberScope);
    if (!decision.ok) {
      logger.log(`${this.toolName}: user denied — ${label}`);
      return this.textError(t.userDenied(label), { denied: true, reason: label });
    }

    if (decision.remember === "session") {
      allowList.rememberSession(this.toolName, this.buildKey(subject), effectiveCwd);
    } else if (decision.remember === "permanent") {
      allowList.rememberPermanent(this.toolName, this.buildKey(subject), effectiveCwd);
    }

    // 6b. Interrupted after approval → do not execute.
    if (signal?.aborted) {
      logger.log(`${this.toolName}: aborted after approval, not executing`);
      return { content: [{ type: "text", text: "(aborted)" }], details: { aborted: true } };
    }

    // 7. Execute — delegate to the native tool.
    logger.log(`${this.toolName}: approved, delegating to native`);
    return this.delegate(params, signal, onUpdate, ctx);
  }

  private textError(text: string, details: Record<string, unknown>): AgentToolResult {
    return { content: [{ type: "text", text }], details, isError: true };
  }
}
