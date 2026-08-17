/**
 * Smart Approve — eval gate.
 *
 * EvalToolGate shadows the native eval tool so dangerous code (subprocess
 * / system-command intent, or subprocess + destructive payload) goes
 * through the same approval pipeline as bash: regex fast path, LLM risk
 * analysis, auto-mode verdict or interactive dialog, then delegation to
 * the native eval tool via ctx.invokeTool() — the native tool keeps its
 * retained kernels, output truncation and cancellation semantics.
 */

import type { ExtensionCtx, AgentToolResult, ZodLike } from "./types";
import { ToolGate, type ToolUpdateCallback } from "./gate";
import { EvalCodeBehaviorAnalyzer } from "./eval-analyzer.ts";

export class EvalToolGate extends ToolGate {
  readonly toolName = "eval";
  protected readonly toolLabel = "Eval";
  protected readonly toolDescription =
    "Execute one Python, JavaScript, Ruby, or Julia cell in a persistent " +
    "language runtime; state survives later calls. Code that starts " +
    "subprocesses or runs system commands requires approval.";
  protected readonly rememberScope = "session" as const;
  protected get strict(): boolean | undefined { return true; }

  private readonly analyzer = new EvalCodeBehaviorAnalyzer();

  protected buildSchema(zod: ZodLike): unknown {
    return zod.object({
      language: zod.enum(["py", "js", "rb", "jl"]),
      code: zod.string(),
      title: zod.string().optional(),
      timeout: zod.number().optional(),
      reset: zod.boolean().optional(),
    });
  }

  protected extractSubject(params: unknown): string {
    const p = params as { code?: unknown };
    return typeof p.code === "string" ? p.code : "";
  }

  protected resolveCwd(_params: unknown, ctx: ExtensionCtx): string {
    return ctx.cwd || process.cwd();
  }

  protected analyze(subject: string) {
    return this.analyzer.analyze(subject);
  }

  protected buildKey(subject: string): string {
    // Trim + collapse whitespace for a stable session allowlist key.
    return subject.replace(/\s+/g, " ").trim();
  }

  protected subjectDisplayLabel(): string {
    return this.deps.t.code;
  }

  protected promptSubjectLabel(): string {
    return this.deps.t.promptCode;
  }

  protected delegate(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    if (!ctx.invokeTool) {
      this.deps.logger.log("eval: ctx.invokeTool unavailable — cannot delegate");
      return Promise.resolve({
        content: [{
          type: "text",
          text: "Error: native eval tool delegation unavailable in this host " +
            "(disable with coverage.eval=false in smart-approve.json)",
        }],
        details: { error: "invokeTool-unavailable" },
        isError: true,
      });
    }
    return ctx.invokeTool(params as Record<string, unknown>, { signal, onUpdate });
  }
}
