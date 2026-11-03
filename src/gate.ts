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
  HostToolInfo,
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
    ctx?: ExtensionCtx,
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
  protectedPathMatcher?: { isProtected(filePath: string, baseCwd?: string): boolean };
}

export type GateAuthorization =
  | { allowed: true }
  | { allowed: false; result: AgentToolResult };

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
  protected abstract analyze(subject: string, params: unknown, ctx: ExtensionCtx): DangerAnalysis;
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

  /** Register a same-name tool gate, reusing the native tool's live schema when supplied. */
  register(pi: ExtensionAPI, nativeTool?: Pick<HostToolInfo, "description" | "parameters">): void {
    pi.registerTool({
      name: this.toolName,
      label: this.toolLabel,
      description: nativeTool?.description
        ? `${nativeTool.description}\n\n${this.toolDescription}`
        : this.toolDescription,
      parameters: nativeTool?.parameters ?? this.buildSchema(pi.zod),
      approval: "exec",
      strict: this.strict,
      execute: (_toolCallId, params, signal, onUpdate, ctx) =>
        this.execute(params, signal, onUpdate, ctx),
    });
  }

  // ── Template method: the shared decision pipeline ──────────────────

  async authorize(
    params: unknown,
    signal: AbortSignal | undefined,
    ctx: ExtensionCtx,
  ): Promise<GateAuthorization> {
    const { config, allowList, contextGatherer, modelInvoker, policy, logger, lang, t } = this.deps;
    const subject = this.extractSubject(params);
    if (!subject.trim()) return { allowed: true };

    const effectiveCwd = this.resolveCwd(params, ctx);
    const hasUI = ctx.hasUI;
    logger.log(`${this.toolName}: subject="${subject.slice(0, 80)}" cwd=${effectiveCwd} hasUI=${hasUI}`);

    const analysis = this.analyze(subject, params, ctx);
    const label = analysis.labels[0]?.[lang] || analysis.labels[0]?.en || "danger";
    const subjectLabel = this.subjectDisplayLabel();

    // Hard-block always wins over the allowlist.
    if (analysis.hardBlocked) {
      logger.log(`${this.toolName}: hard-blocked (${label})`);
      return {
        allowed: false,
        result: this.textError(
          `Blocked: ${label}\n${subjectLabel}: ${subject}`,
          { blocked: true, reason: label },
        ),
      };
    }

    if (
      !analysis.requiresConfirmation &&
      config.rememberDecisions &&
      allowList.isAllowed(this.toolName, this.buildKey(subject), effectiveCwd)
    ) {
      return { allowed: true };
    }

    if (analysis.behaviors.length === 0 && !analysis.requiresConfirmation) {
      return { allowed: true };
    }

    const autoMode = config.mode === "auto";
    if (analysis.requiresConfirmation && !hasUI) {
      logger.log(`${this.toolName}: protected operation blocked (no UI) — ${label}`);
      return {
        allowed: false,
        result: this.textError(
          `${t.blockedNoUI(label)}\n${subjectLabel}: ${subject}`,
          { blocked: true, reason: "no-ui" },
        ),
      };
    }
    if (!hasUI && !(autoMode && config.autoInHeadless)) {
      logger.log(`${this.toolName}: blocked (no UI) — ${label}`);
      return {
        allowed: false,
        result: this.textError(
          `${t.blockedNoUI(label)}\n${subjectLabel}: ${subject}`,
          { blocked: true, reason: "no-ui" },
        ),
      };
    }

    let aiResult: RiskAnalysis | null = null;
    let analysisText: string | null = null;
    if (config.llmAnalysis && !analysis.requiresConfirmation) {
      ctx.ui.setStatus("smart-approve", t.analyzing);
      try {
        const sessionCtx = contextGatherer.gather(ctx, config.contextMaxChars);
        const contextSection = contextGatherer.format(sessionCtx, t);
        const behaviorLabels = analysis.labels.map((item) => item[lang] || item.en);
        logger.log(
          `${this.toolName}: analyzeRisk subject="${subject.slice(0, 80)}" behaviors=[${behaviorLabels.join(",")}]`,
        );
        aiResult = await modelInvoker.analyze(
          subject,
          this.promptSubjectLabel(),
          behaviorLabels,
          contextSection,
          t,
          config.model,
          signal,
          ctx,
        );
        analysisText = formatAnalysis(aiResult, t);
        logger.log(`${this.toolName}: analysisText=${analysisText ? "OK" : "null"}`);
      } catch (e) {
        logger.log(`${this.toolName}: LLM analysis failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        ctx.ui.setStatus("smart-approve", undefined);
      }
    }

    if (signal?.aborted) {
      logger.log(`${this.toolName}: aborted during analysis`);
      return {
        allowed: false,
        result: { content: [{ type: "text", text: "(aborted)" }], details: { aborted: true } },
      };
    }

    if (autoMode && !analysis.requiresConfirmation) {
      const decision = policy.decide(aiResult, analysis.denyTier);
      logger.log(`${this.toolName}: auto decision=${decision.verdict} reason=${decision.reason} (${label})`);
      if (decision.verdict === "allow") {
        ctx.ui.notify?.(t.autoAllowed(label), "info");
        return { allowed: true };
      }
      ctx.ui.notify?.(t.autoBlocked(label), "warning");
      return {
        allowed: false,
        result: this.textError(
          `${t.autoBlocked(label)}\n${subjectLabel}: ${subject}`,
          { blocked: true, reason: "auto" },
        ),
      };
    }

    const title = t.confirmTitle(label);
    const body = analysis.requiresConfirmation
      ? `${subjectLabel}: ${subject}\n\n${t.allowPrompt}`
      : analysisText
        ? `${analysisText}\n\n────────\n${subjectLabel}: ${subject}\n\n${t.allowPrompt}`
        : `${t.analysisUnavailable}\n\n${subjectLabel}: ${subject}\n\n${t.allowPrompt}`;
    const decision = await confirmWithRemember(
      ctx,
      title,
      body,
      t,
      config.rememberDecisions,
      this.rememberScope,
    );
    if (!decision.ok) {
      logger.log(`${this.toolName}: user denied — ${label}`);
      return {
        allowed: false,
        result: this.textError(t.userDenied(label), { denied: true, reason: label }),
      };
    }

    if (decision.remember === "session") {
      allowList.rememberSession(this.toolName, this.buildKey(subject), effectiveCwd);
    } else if (decision.remember === "permanent") {
      allowList.rememberPermanent(this.toolName, this.buildKey(subject), effectiveCwd);
    }
    if (signal?.aborted) {
      logger.log(`${this.toolName}: aborted after approval, not executing`);
      return {
        allowed: false,
        result: { content: [{ type: "text", text: "(aborted)" }], details: { aborted: true } },
      };
    }
    return { allowed: true };
  }

  async execute(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    const authorization = await this.authorize(params, signal, ctx);
    if (!authorization.allowed) return authorization.result;
    if (!this.extractSubject(params).trim()) {
      this.deps.logger.log(`${this.toolName}: empty subject, passing through`);
      return this.onEmpty(params, signal, onUpdate, ctx);
    }
    this.deps.logger.log(`${this.toolName}: approved, delegating to native`);
    return this.delegate(params, signal, onUpdate, ctx);
  }

  private textError(text: string, details: Record<string, unknown>): AgentToolResult {
    return { content: [{ type: "text", text }], details, isError: true };
  }
}
