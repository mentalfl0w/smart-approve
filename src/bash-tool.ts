/**
 * Smart Approve — bash gate.
 *
 * BashToolGate extends the shared ToolGate template with bash-specific
 * hooks: cd-prefix extraction, the command behavior analyzer, the
 * allowlist key, and delegation to the native bash tool via
 * ctx.invokeTool() (inheriting shell path resolution, env hardening,
 * PTY and output truncation from the native implementation).
 */

import type { ExtensionCtx, AgentToolResult, ZodLike } from "./types";
import type { I18n } from "./i18n";
import { ToolGate, type ToolUpdateCallback } from "./gate";
import { analyzeCommand } from "./behaviors";

/** Extract the leading `cd <path> && ...` into a cwd, like OMP's BashTool. */
function extractCwd(command: string, cwd: string): { cmd: string; cwd: string } {
  const m = command.match(/^\s*cd\s+(['"]?)([^'"]+)\1\s*&&\s*(.+)$/s);
  if (!m) return { cmd: command, cwd };
  return { cmd: m[3].trim(), cwd: m[2].trim() };
}

export class BashToolGate extends ToolGate {
  readonly toolName = "bash";
  protected readonly toolLabel = "Bash";
  protected readonly toolDescription =
    "Executes a bash command. Dangerous commands (force-push, rm -rf, " +
    "writes to system paths, etc.) require interactive approval. Safe " +
    "commands execute with zero interruption.";
  protected readonly rememberScope = "both" as const;

  protected buildSchema(zod: ZodLike): unknown {
    return zod.object({
      command: zod.string().describe("The bash command to execute"),
      timeout: zod.number().optional().describe("Timeout in seconds (max 3600)"),
      cwd: zod.string().optional().describe("Working directory"),
    });
  }

  /** Analysis subject = the cd-stripped command; execution still
   *  delegates the RAW command so the native tool does its own cd
   *  extraction, cwd resolution and path validation. */
  protected extractSubject(params: unknown): string {
    const p = params as { command?: unknown };
    return typeof p.command === "string" ? p.command : "";
  }

  protected resolveCwd(params: unknown, ctx: ExtensionCtx): string {
    const p = params as { command?: string; cwd?: string };
    const baseCwd = ctx.cwd || process.cwd();
    const { cwd: extractedCwd } = extractCwd(p.command ?? "", baseCwd);
    // Analysis cwd must match the real execution cwd: the cd-prefix path
    // when one is present, else the explicit cwd param, else session cwd.
    return extractedCwd !== baseCwd ? extractedCwd : p.cwd ?? baseCwd;
  }

  protected analyze(subject: string) {
    return analyzeCommand(subject);
  }

  protected buildKey(subject: string): string {
    return subject;
  }

  protected subjectDisplayLabel(): string {
    return this.deps.t.command;
  }

  protected promptSubjectLabel(): string {
    return this.deps.t.promptCommand;
  }

  /** Empty command → "(no command)", matching the native tool's shape. */
  protected async onEmpty(): Promise<AgentToolResult> {
    return { content: [{ type: "text", text: "(no command)" }] };
  }

  protected delegate(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    const p = params as { command?: string; timeout?: number; cwd?: string };
    const nativeParams: Record<string, unknown> = { command: p.command ?? "" };
    if (p.cwd) nativeParams.cwd = p.cwd;
    if (p.timeout) nativeParams.timeout = p.timeout;

    if (!ctx.invokeTool) {
      this.deps.logger.log("bash: ctx.invokeTool unavailable — cannot delegate");
      return Promise.resolve({
        content: [{ type: "text", text: "Error: native bash tool delegation unavailable in this host" }],
        details: { error: "invokeTool-unavailable" },
        isError: true,
      });
    }
    return ctx.invokeTool(nativeParams, { signal, onUpdate });
  }
}
