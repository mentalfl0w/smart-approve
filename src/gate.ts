/**
 * Smart Approve — shared approval gate (template method).
 *
 * ToolGate owns the decision pipeline that was previously bash-only:
 *
 *   hard-block -> safe pass-through -> allow-list/model/user decision
 *   -> remember -> delegate
 *
 * Concrete gates (bash, eval) supply the tool-specific hooks:
 * analyze() / buildKey() / delegate(), plus the schema and subject
 * extraction.  The flow itself never varies, so every covered tool gets
 * identical approval semantics.
 */

import type {
  ExtensionAPI,
  ExtensionCtx,
  AgentToolResult,
  DangerAnalysis,
  ZodLike,
  HostToolInfo,
} from "./types";
import type { ApprovalDeps } from "./approval";
import { ApprovalFlow } from "./approval";

export type {
  AllowListLike,
  ContextGathererLike,
  ModelInvokerLike,
} from "./approval";

/** Shared collaborators injected into every gate instance. */
export interface GateDeps extends ApprovalDeps {
  protectedPathMatcher?: { isProtected(filePath: string, baseCwd?: string): boolean };
  /** Live host tool inventory.  Eval uses it to recognize nested MCP calls
   *  and MCP namespace globals; read lazily because MCP tools connect after
   *  session start. */
  hostTools?: () => readonly HostToolInfo[];
}

export type GateAuthorization =
  | { allowed: true }
  | { allowed: false; result: AgentToolResult };

/** Tool update callback, matching ToolDefinition.execute's onUpdate. */
export type ToolUpdateCallback =
  ((update: { content: unknown[]; details?: unknown }) => void) | undefined;

export abstract class ToolGate {
  private readonly approval: ApprovalFlow;

  // Public so concrete gates can be constructed by the orchestrator and
  // tests; the class is abstract, so it cannot be instantiated directly.
  constructor(protected readonly deps: GateDeps) {
    this.approval = new ApprovalFlow(deps);
  }

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
    const { logger, lang, t } = this.deps;
    const subject = this.extractSubject(params);
    if (!subject.trim()) return { allowed: true };

    const effectiveCwd = this.resolveCwd(params, ctx);
    logger.log(`${this.toolName}: subject="${subject.slice(0, 80)}" cwd=${effectiveCwd} hasUI=${ctx.hasUI}`);

    const analysis = this.analyze(subject, params, ctx);
    const label = analysis.labels[0]?.[lang] || analysis.labels[0]?.en || "danger";
    const subjectLabel = this.subjectDisplayLabel();

    // Hard blocks precede every collaborator: no allow-list entry, model
    // verdict, mode, or memory choice can override them.
    if (analysis.hardBlocked) {
      logger.log(`${this.toolName}: hard-blocked (${label})`);
      return {
        allowed: false,
        result: {
          content: [{
            type: "text",
            text: `Blocked: ${label}\n${t.decisionSourceHardBlock}\n${subjectLabel}: ${subject}`,
          }],
          details: { blocked: true, reason: label },
          isError: true,
        },
      };
    }

    // Safe operations stay zero-interruption: no model call, no dialog.
    if (analysis.behaviors.length === 0 && !analysis.requiresConfirmation) {
      return { allowed: true };
    }

    const memoryEligible = analysis.memoryEligible !== false;
    const outcome = await this.approval.decide(
      {
        toolName: this.toolName,
        label,
        subjectLabel,
        promptSubject: subject,
        promptSubjectLabel: this.promptSubjectLabel(),
        displaySubject: subject,
        behaviorLabels: analysis.labels.map((item) => item[lang] || item.en),
        memoryKey: memoryEligible ? this.buildKey(subject) : null,
        cwd: effectiveCwd,
        rememberScope: this.rememberScope,
      },
      ctx,
      signal,
    );
    if (outcome.allowed) return { allowed: true };
    return { allowed: false, result: outcome.result };
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
}
