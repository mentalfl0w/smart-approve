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
import * as path from "node:path";
import { resolveFilesystemPathCandidates } from "./paths.ts";

import type { ExtensionCtx, AgentToolResult, HostToolInfo, ZodLike } from "./types";
import { ToolGate, type ToolUpdateCallback } from "./gate";
import {
  EvalCodeBehaviorAnalyzer,
  TASK_GROUP_PROC_CANCEL_MARKER,
  extractEvalWriteTargets,
  type EvalHostToolContext,
} from "./eval-analyzer.ts";
import { makeLabel } from "./i18n.ts";
import { isSensitiveWorkingDirectory } from "./behaviors.ts";
import { isUnresolvedCwd, UNRESOLVED_CWD } from "./bash-tool.ts";

/** Derive the Eval MCP surface from the live session-tool inventory.  OMP
 *  publishes `mcpServerName` for MCP-backed tools even while `mcp.evalNamespaces`
 *  keeps the tools out of the active top-level list. */
function collectEvalHostContext(
  tools: readonly HostToolInfo[] | undefined,
): EvalHostToolContext | undefined {
  if (!tools || tools.length === 0) return undefined;
  const mcpToolNames = new Set<string>();
  const mcpServerNames = new Set<string>();
  for (const tool of tools) {
    if (typeof tool.mcpServerName === "string" && tool.mcpServerName) {
      mcpServerNames.add(tool.mcpServerName);
      if (tool.name) mcpToolNames.add(tool.name);
    } else if (tool.name.startsWith("mcp__")) {
      mcpToolNames.add(tool.name);
    }
  }
  return mcpToolNames.size === 0 && mcpServerNames.size === 0
    ? undefined
    : { mcpToolNames, mcpServerNames };
}

export class EvalToolGate extends ToolGate {
  readonly toolName = "eval";
  protected readonly toolLabel = "Eval";
  protected readonly toolDescription =
    "Execute one Python or JavaScript cell in a persistent language runtime. " +
    "Known high-risk launches and system-sensitive writes are hard-blocked; subprocesses, protected-path writes, and MCP/host-tool calls require review. " +
    `Capability marker: ${TASK_GROUP_PROC_CANCEL_MARKER}`;
  protected readonly rememberScope = "session" as const;
  protected get strict(): boolean | undefined { return true; }

  private readonly analyzer = new EvalCodeBehaviorAnalyzer();

  private hostToolContext(): EvalHostToolContext | undefined {
    try {
      return collectEvalHostContext(this.deps.hostTools?.());
    } catch {
      // Inventory is optional.  Direct `tool.mcp__*` names still match the
      // MCP prefix; namespace globals need the inventory to be recognized.
      return undefined;
    }
  }

  protected buildSchema(zod: ZodLike): unknown {
    return zod.object({
      language: zod.enum(["py", "js"]),
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

  protected resolveCwd(params: unknown, ctx: ExtensionCtx): string {
    let cwd: unknown;
    if (typeof params === "object" && params !== null && "cwd" in params) cwd = params.cwd;
    const base = ctx.cwd || process.cwd();
    if (typeof cwd !== "string" || !cwd) return base;
    if (isUnresolvedCwd(cwd)) return UNRESOLVED_CWD;
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(cwd)) return cwd;
    const candidates = resolveFilesystemPathCandidates(cwd, base);
    return candidates[candidates.length - 1] ?? path.resolve(base, cwd);
  }

  protected analyze(subject: string, params: unknown, ctx: ExtensionCtx) {
    const language = typeof params === "object" && params !== null && "language" in params
      ? params.language === "py" ? "py" : "js"
      : undefined;
    const cwd = this.resolveCwd(params, ctx);
    const sessionCwd = ctx.cwd || process.cwd();
    const unresolvedCwd = isUnresolvedCwd(cwd);
    const analysis = this.analyzer.analyze(
      subject,
      language,
      cwd,
      sessionCwd,
      this.hostToolContext(),
    );
    const writeTargets = extractEvalWriteTargets(subject, language);
    const hostToolTargets = writeTargets.hostToolTargets ?? [];
    const writeCwds = unresolvedCwd ? [sessionCwd] : [cwd];
    let currentCwd: string | undefined = unresolvedCwd ? undefined : cwd;
    let sensitiveCwd = false;
    let unresolvedCwdOperation = false;

    for (const target of writeTargets.cwdPaths) {
      if (
        currentCwd === undefined &&
        !path.isAbsolute(target) &&
        !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(target)
      ) {
        unresolvedCwdOperation = true;
        continue;
      }
      const baseCwd = currentCwd ?? sessionCwd;
      const candidates = resolveFilesystemPathCandidates(target, baseCwd);
      const resolvedCwd = candidates[candidates.length - 1] ?? path.resolve(baseCwd, target);
      if (isSensitiveWorkingDirectory(resolvedCwd, sessionCwd)) sensitiveCwd = true;
      writeCwds.push(...candidates);
      currentCwd = resolvedCwd;
    }

    const relativeTarget = (target: string): boolean =>
      !path.isAbsolute(target) && !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(target);
    const relativeWriteAfterDynamicCwd =
      writeTargets.cwdDynamic && writeTargets.paths.some(relativeTarget);
    const dynamicWrite =
      writeTargets.dynamic ||
      relativeWriteAfterDynamicCwd ||
      (unresolvedCwd && writeTargets.paths.some(relativeTarget));
    const dynamicCwdWithSpawn =
      (writeTargets.cwdDynamic || unresolvedCwd) &&
      analysis.behaviors.includes("eval-process-spawn");
    const behaviors = new Set(analysis.behaviors);
    let hardBlocked = analysis.hardBlocked || sensitiveCwd;
    let hardBlockedBySystemWrite = false;
    let requiresConfirmation = analysis.requiresConfirmation ?? false;
    let denyTier = analysis.denyTier;

    if (sensitiveCwd) behaviors.add("eval-sensitive-working-directory");
    // `xd://` writes are host-tool invocations, not filesystem writes; keep
    // them reviewable so the model sees the tool name and its arguments.
    // Without a valid verdict they remain deny-tier and auto mode blocks.
    if (hostToolTargets.length > 0) {
      behaviors.add("eval-host-tool-invocation");
      // An `xd://` write dispatches a host tool whose side effects are not
      // visible to the file-target analysis.  Without a model verdict, auto
      // mode must not treat that as safe.
      denyTier = true;
    }
    if (behaviors.has("eval-mcp-tool-invocation")) denyTier = true;

    for (const target of writeTargets.paths) {
      const candidates = writeCwds.flatMap((writeCwd) =>
        resolveFilesystemPathCandidates(target, writeCwd),
      );
      const normalizedCandidates = candidates.map((candidate) => candidate.replace(/\\/g, "/"));
      if (
        normalizedCandidates.some((normalized) =>
          /^(?:\/private)?\/etc\/(?:passwd|shadow|sudoers|hosts)(?:$|[./])/i.test(normalized) ||
          /^\/dev\/(?:sd[a-z]\d*|nvme\d+(?:n\d+)?(?:p\d+)?|disk\d+(?:s\d+)?|hd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|mmcblk\d+(?:p\d+)?|mapper\/[^/]+|md\d+|sg\d+|st\d+|nst\d+)$/i.test(normalized)
        )
      ) {
        hardBlocked = true;
        hardBlockedBySystemWrite = true;
      } else if (
        this.deps.protectedPathMatcher?.isProtected(target, unresolvedCwd ? sessionCwd : cwd) ||
        candidates.some((candidate) =>
          this.deps.protectedPathMatcher?.isProtected(candidate, unresolvedCwd ? sessionCwd : cwd),
        )
      ) {
        behaviors.add("eval-protected-file-write");
        requiresConfirmation = true;
      }
    }

    if (dynamicWrite) {
      behaviors.add("eval-dynamic-file-write");
      denyTier = true;
      requiresConfirmation = true;
    }
    if (dynamicCwdWithSpawn || unresolvedCwdOperation) {
      behaviors.add("eval-unresolved-working-directory");
      requiresConfirmation = true;
    }

    const nextBehaviors = [...behaviors];
    const labels = [...analysis.labels];
    if (
      sensitiveCwd &&
      !analysis.behaviors.includes("eval-sensitive-working-directory")
    ) {
      labels.push(makeLabel(
        "Eval code changes to a sensitive working directory",
        "Eval 代码切换到敏感工作目录",
      ));
    }
    if (behaviors.has("eval-protected-file-write")) {
      labels.push(makeLabel("Writes a protected file from Eval code", "Eval 代码写入受保护文件"));
    }
    if (behaviors.has("eval-host-tool-invocation")) {
      labels.push(makeLabel(
        "Invokes a host tool from Eval code",
        "Eval 代码调用宿主工具",
      ));
    }
    if (dynamicWrite) {
      labels.push(makeLabel(
        "Eval writes to a path or working directory that cannot be resolved statically",
        "Eval 写入路径或工作目录无法静态确定",
      ));
    }
    if (dynamicCwdWithSpawn || unresolvedCwdOperation) {
      labels.push(makeLabel(
        "Eval uses a working directory that cannot be resolved statically",
        "Eval 使用了无法静态确定的工作目录",
      ));
    }
    if (hardBlockedBySystemWrite) {
      labels.push(makeLabel("Eval writes a system-sensitive file", "Eval 代码写入系统敏感文件"));
    }
    return { ...analysis, behaviors: nextBehaviors, labels, hardBlocked, denyTier, requiresConfirmation };
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
