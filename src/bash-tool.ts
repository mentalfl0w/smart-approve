/**
 * Smart Approve — bash gate.
 *
 * BashToolGate extends the shared ToolGate template with bash-specific
 * hooks: cd-prefix extraction, the command behavior analyzer, the
 * allowlist key, and delegation to the native bash tool via
 * ctx.invokeTool() (inheriting shell path resolution, env hardening,
 * PTY and output truncation from the native implementation).
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionCtx, AgentToolResult, DangerAnalysis, ZodLike } from "./types";
import { ToolGate, type ToolUpdateCallback } from "./gate";
import { analyzeBashOperation, analyzeCommand } from "./behaviors";
import { makeLabel } from "./i18n";
import { resolveFilesystemPathCandidates } from "./paths";
import {
  forgetProcService,
  sessionIdOf,
  trackInteractiveService,
} from "./proc-input-guard.ts";

/** Sentinel used when the effective cwd depends on runtime shell state. */
export const UNRESOLVED_CWD = "\0unresolved-cwd";

export const UNRESOLVED_CWD_LABEL = makeLabel(
  "Working directory cannot be resolved without running the shell",
  "工作目录需要执行 shell 才能确定",
);

export function isUnresolvedCwd(value: string): boolean {
  return value === UNRESOLVED_CWD;
}

interface PathExpansion {
  expandVariables: boolean;
  expandTilde: boolean;
}

/** Expand only the HOME forms whose value is known without running the shell. */
function expandLiteralPath(value: string, options: PathExpansion): string | undefined {
  let expanded = value;
  if (!expanded) return undefined;
  if (options.expandTilde) {
    if (expanded === "~") expanded = process.env.HOME || os.homedir();
    else if (expanded.startsWith("~/")) {
      expanded = path.join(process.env.HOME || os.homedir(), expanded.slice(2));
    } else if (expanded.startsWith("~")) {
      // `~user` needs a passwd lookup; do not guess.
      return undefined;
    }
  }
  if (options.expandVariables) {
    const placeholder = "\0HOME\0";
    expanded = expanded
      .replace(/\$\{HOME\}/g, placeholder)
      .replace(/\$HOME(?![A-Za-z0-9_])/g, placeholder);
    if (/[$`]/.test(expanded)) return undefined;
    expanded = expanded.split(placeholder).join(process.env.HOME || os.homedir());
  }
  if (!expanded) return undefined;
  return expanded;
}

interface LeadingCwd {
  /** Literal target after static HOME expansion. */
  cwd?: string;
  /** The leading cd target needs shell evaluation. */
  unresolved?: boolean;
}

interface ParsedCdTarget {
  /** Literal target after static HOME expansion. */
  target?: string;
  /** Index after the operand (or after cd when it is bare). */
  end: number;
  /** The operand is runtime-dependent or uses an unsupported option. */
  unresolved?: boolean;
}

/** Parse the cd operand starting at `commandIndex` (just after `cd`). */
function parseCdTarget(command: string, commandIndex: number): ParsedCdTarget {
  let index = commandIndex;
  const skipWhitespace = (): void => {
    while (index < command.length && /[ \t]/.test(command[index])) index++;
  };
  skipWhitespace();

  // cd supports -L/-P (and -e), possibly clustered or repeated, before `--`.
  while (index < command.length && command[index] === "-" && !command.startsWith("--", index)) {
    const next = command[index + 1];
    if (next === undefined || /\s/.test(next)) {
      // Lone "-" means OLDPWD, which is runtime state.
      return { unresolved: true, end: index };
    }
    let cursor = index + 1;
    let valid = true;
    while (cursor < command.length && !/[\s;&|()<>]/.test(command[cursor])) {
      const flag = command[cursor];
      if (flag !== "L" && flag !== "P" && flag !== "e") {
        valid = false;
        break;
      }
      cursor++;
    }
    if (!valid) return { unresolved: true, end: index };
    index = cursor;
    skipWhitespace();
  }

  let endOfOptions = false;
  if (
    command.startsWith("--", index) &&
    (index + 2 >= command.length || /[\s;&|#]/.test(command[index + 2]))
  ) {
    index += 2;
    skipWhitespace();
    endOfOptions = true;
  }

  // Bare `cd`, or one followed directly by a separator/comment, goes HOME.
  if (
    index >= command.length ||
    command.startsWith("&&", index) ||
    command[index] === ";" ||
    command[index] === "\n" ||
    command[index] === "\r" ||
    command[index] === "#"
  ) {
    return { target: process.env.HOME || os.homedir(), end: index };
  }
  if (!endOfOptions && command[index] === "-") {
    return { unresolved: true, end: index };
  }

  let raw: string;
  let expansion: PathExpansion = { expandVariables: true, expandTilde: true };
  const quote = command[index];
  if (quote === "'") {
    const end = command.indexOf("'", index + 1);
    if (end === -1) return { unresolved: true, end: index };
    raw = command.slice(index + 1, end);
    expansion = { expandVariables: false, expandTilde: false };
    index = end + 1;
  } else if (quote === '"') {
    let value = "";
    let cursor = index + 1;
    while (cursor < command.length) {
      const ch = command[cursor];
      if (ch === "\\") {
        const next = command[cursor + 1];
        if (next === undefined) return { unresolved: true, end: index };
        if (next === "\n") {
          cursor += 2;
          continue;
        }
        if (next === "$" || next === "`" || next === '"' || next === "\\") {
          value += next;
          cursor += 2;
        } else {
          value += ch;
          cursor++;
        }
        continue;
      }
      if (ch === '"') break;
      value += ch;
      cursor++;
    }
    if (cursor >= command.length) return { unresolved: true, end: index };
    raw = value;
    expansion = { expandVariables: true, expandTilde: false };
    index = cursor + 1;
  } else {
    let value = "";
    let cursor = index;
    let escapedDynamic = false;
    let literalTilde = false;
    while (cursor < command.length) {
      const ch = command[cursor];
      if (/\s/.test(ch) || ch === "&" || ch === ";" || ch === "|" || ch === "<" || ch === ">" || ch === "(" || ch === ")") break;
      // Mixed quoting/concatenation cannot be mapped to one literal path.
      if (ch === "'" || ch === '"') return { unresolved: true, end: index };
      if (ch === "\\") {
        const next = command[cursor + 1];
        if (next === undefined) return { unresolved: true, end: index };
        if (next === "\n") {
          cursor += 2;
          continue;
        }
        // `\$HOME` / `` \`cmd` `` are literal shell text; do not expand them.
        if (next === "$" || next === "`") escapedDynamic = true;
        else if (value === "" && next === "~") literalTilde = true;
        value += next;
        cursor += 2;
        continue;
      }
      value += ch;
      cursor++;
    }
    if (!value) return { unresolved: true, end: index };
    if (escapedDynamic) return { unresolved: true, end: index };
    // Unquoted glob/brace expansion changes the target at runtime.
    if (/[*?\[\]{}]/.test(value)) return { unresolved: true, end: index };
    raw = value;
    expansion = { expandVariables: true, expandTilde: !literalTilde };
    index = cursor;
  }

  const target = expandLiteralPath(raw, expansion);
  if (target === undefined || (!endOfOptions && target === "-")) {
    return { unresolved: true, end: index };
  }
  return { target, end: index };
}

/** Split shell text at `;`, newline, `&&`, and `||`, ignoring quotes/comments. */
function splitShellSegments(command: string): string[] {
  const segments: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;
  let commandSubDepth = 0;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote !== undefined) {
      if (quote === "'") {
        if (ch === "'") quote = undefined;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = undefined;
      }
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      continue;
    }
    if (commandSubDepth > 0) {
      if (ch === "(") commandSubDepth++;
      else if (ch === ")") commandSubDepth--;
      continue;
    }
    if (ch === "$" && command[i + 1] === "(") {
      commandSubDepth = 1;
      i++;
      continue;
    }
    if (ch === "#" && (i === 0 || /[\s;&|]/.test(command[i - 1]))) {
      const newline = command.indexOf("\n", i);
      segments.push(command.slice(start, i));
      if (newline === -1) {
        start = command.length;
        break;
      }
      start = newline + 1;
      i = newline;
      continue;
    }
    if (ch === "\n" || ch === ";") {
      segments.push(command.slice(start, i));
      start = i + 1;
      continue;
    }
    if ((ch === "&" && command[i + 1] === "&") || (ch === "|" && command[i + 1] === "|")) {
      segments.push(command.slice(start, i));
      i++;
      start = i + 1;
    }
  }
  segments.push(command.slice(start));
  return segments;
}

/** True when only spaces or a trailing comment follow the cd operand. */
function cdOperandEndsSegment(command: string, end: number): boolean {
  let index = end;
  while (index < command.length && /[ \t\r]/.test(command[index])) index++;
  return index >= command.length || command[index] === "#";
}

/** Remove grouping/control prefixes so `(cd ...)`, `then cd ...` are scanned. */
function stripSegmentPrefix(segment: string): string {
  let value = segment.trim();
  while (true) {
    const next = value
      .replace(/^[({]+\s*/, "")
      .replace(/^(?:then|do|else|elif|if|while|until)\b\s*/, "")
      .trim();
    if (next === value) return value;
    value = next;
  }
}

/** Collect literal cd targets from every command segment; flag dynamic ones. */
export function collectCdTargets(command: string): { targets: string[]; dynamic: boolean } {
  const targets: string[] = [];
  let dynamic = false;
  for (const raw of splitShellSegments(command)) {
    const segment = stripSegmentPrefix(raw);
    const match = /^cd(?=\s|$)/.exec(segment);
    if (!match) continue;
    const parsed = parseCdTarget(segment, match[0].length);
    if (
      parsed.unresolved ||
      parsed.target === undefined ||
      !cdOperandEndsSegment(segment, parsed.end)
    ) {
      dynamic = true;
    } else {
      targets.push(parsed.target);
    }
  }
  return { targets, dynamic };
}

/** Resolve one literal cwd candidate and prefer its canonical path. */
function resolveCwdCandidate(candidate: string, baseCwd: string): string {
  const base = path.resolve(baseCwd);
  if (isUnresolvedCwd(candidate)) return candidate;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(candidate)) return candidate;
  const resolved = path.resolve(base, candidate);
  const candidates = resolveFilesystemPathCandidates(resolved, base);
  return candidates[candidates.length - 1] ?? resolved;
}

/** Resolve the cwd in effect before the command's own cd segments. */
function resolveRequestedCwd(requestedCwd: string | undefined, baseCwd: string): string {
  const base = path.resolve(baseCwd);
  if (requestedCwd === undefined || requestedCwd === "") {
    return resolveCwdCandidate(base, base);
  }
  const expanded = expandLiteralPath(requestedCwd, { expandVariables: true, expandTilde: true });
  if (expanded === undefined) return UNRESOLVED_CWD;
  return resolveCwdCandidate(expanded, base);
}

/** True when a resolved path is an existing directory. */
function isExistingDirectory(value: string): boolean {
  try {
    return fs.statSync(value).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Extract the first command's cd target as the analysis cwd. Later cd
 * segments are checked separately by collectCdTargets.
 */
function extractLeadingCwd(command: string): LeadingCwd {
  let start = 0;
  while (start < command.length) {
    const ch = command[start];
    if (/\s/.test(ch)) {
      start++;
      continue;
    }
    if (ch === "#") {
      const newline = command.indexOf("\n", start);
      if (newline === -1) return {};
      start = newline + 1;
      continue;
    }
    break;
  }
  const match = /^cd(?=\s|$)/.exec(command.slice(start));
  if (!match) return {};
  const parsed = parseCdTarget(command, start + match[0].length);
  if (parsed.unresolved || parsed.target === undefined) return { unresolved: true };

  let index = parsed.end;
  while (index < command.length && /[ \t\r]/.test(command[index])) index++;
  const newlineTerminated = index < command.length && command[index] === "\n";
  while (index < command.length && /\s/.test(command[index])) index++;
  if (
    index < command.length &&
    !command.startsWith("&&", index) &&
    command[index] !== ";" &&
    command[index] !== "#" &&
    !newlineTerminated
  ) {
    return { unresolved: true };
  }
  return { cwd: parsed.target };
}

/** Effective cwd for analysis and allowlist scoping; native input is untouched. */
function resolveEffectiveCwd(
  command: string,
  requestedCwd: string | undefined,
  baseCwd: string,
): string {
  const leading = extractLeadingCwd(command);
  if (leading.unresolved) return UNRESOLVED_CWD;
  if (leading.cwd !== undefined) return resolveCwdCandidate(leading.cwd, baseCwd);
  return resolveRequestedCwd(requestedCwd, baseCwd);
}

export class BashToolGate extends ToolGate {
  readonly toolName = "bash";
  protected readonly toolLabel = "Bash";
  protected readonly toolDescription =
    "Executes a bash command. Risky commands (force-push, rm -rf, " +
    "writes to system paths, etc.) are hard-blocked or routed through the " +
    "configured review/auto policy. Safe commands execute with zero interruption.";
  protected readonly rememberScope = "both" as const;
  protected get strict(): boolean | undefined { return true; }

  protected buildSchema(zod: ZodLike): unknown {
    return zod.object({
      command: zod.string().describe("The bash command to execute"),
      timeout: zod.number().optional().describe("Timeout in seconds (max 3600)"),
      cwd: zod.string().optional().describe("Working directory"),
    });
  }

  protected extractSubject(params: unknown): string {
    if (typeof params !== "object" || params === null || !("command" in params)) return "";
    return typeof params.command === "string" ? params.command : "";
  }

  protected resolveCwd(params: unknown, ctx: ExtensionCtx): string {
    const raw = typeof params === "object" && params !== null
      ? params as Record<string, unknown>
      : {};
    return resolveEffectiveCwd(
      typeof raw.command === "string" ? raw.command : "",
      typeof raw.cwd === "string" ? raw.cwd : undefined,
      ctx.cwd || process.cwd(),
    );
  }

  protected analyze(subject: string, params: unknown, ctx: ExtensionCtx) {
    const rawParams = typeof params === "object" && params !== null
      ? params as Record<string, unknown>
      : {};
    const requestedCwd = typeof rawParams.cwd === "string" ? rawParams.cwd : undefined;
    const cwd = this.resolveCwd(params, ctx);
    const leadingUnresolved = isUnresolvedCwd(cwd);
    const sessionBase = path.resolve(ctx.cwd || process.cwd());
    const sessionCandidates = resolveFilesystemPathCandidates(sessionBase, sessionBase);
    const sessionCwd = sessionCandidates[sessionCandidates.length - 1] ?? sessionBase;

    const analysis = leadingUnresolved
      ? analyzeCommand(subject)
      : analyzeBashOperation(subject, cwd, sessionCwd);

    let hardBlocked = analysis.hardBlocked;
    let denyTier = analysis.denyTier;
    let requiresConfirmation = analysis.requiresConfirmation ?? false;
    const behaviors = [...analysis.behaviors];
    const labels = [...analysis.labels];
    const merge = (extra: DangerAnalysis): void => {
      for (const behavior of extra.behaviors) {
        if (!behaviors.includes(behavior)) behaviors.push(behavior);
      }
      for (const label of extra.labels) {
        if (!labels.some((item) => item.en === label.en && item.zh === label.zh)) {
          labels.push(label);
        }
      }
      if (extra.hardBlocked) hardBlocked = true;
      if (extra.denyTier) denyTier = true;
      if (extra.requiresConfirmation) requiresConfirmation = true;
    };

    const scanned = collectCdTargets(subject);
    const initialCwd = resolveRequestedCwd(requestedCwd, sessionBase);
    const initialSentinel = isUnresolvedCwd(initialCwd);
    const initialVirtual = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(initialCwd);
    let chainUnknown =
      leadingUnresolved ||
      scanned.dynamic ||
      initialSentinel ||
      (initialVirtual && scanned.targets.length > 0);
    let chainTrusted =
      !leadingUnresolved && !scanned.dynamic && !initialSentinel && !initialVirtual;
    let currentCwd = initialCwd;
    for (const target of scanned.targets) {
      const absoluteTarget = path.isAbsolute(target);
      if (!chainTrusted) {
        if (!absoluteTarget) continue;
        // Once the relative chain is unknown, an absolute cd can still enter
        // a sensitive directory and must be checked independently.
        merge(analyzeBashOperation("", resolveCwdCandidate(target, sessionCwd), sessionCwd));
        continue;
      }
      const resolved = resolveCwdCandidate(path.resolve(currentCwd, target), currentCwd);
      // Check sensitivity before existence so a missing sensitive target still
      // hard-blocks instead of downgrading to a generic confirmation.
      merge(analyzeBashOperation("", resolved, sessionCwd));
      if (isUnresolvedCwd(resolved) || !isExistingDirectory(resolved)) {
        chainTrusted = false;
        continue;
      }
      currentCwd = resolved;
    }
    if (!chainTrusted && scanned.targets.length > 0) chainUnknown = true;

    if (chainUnknown) {
      requiresConfirmation = true;
      denyTier = true;
      if (!behaviors.includes("bash-unresolved-working-directory")) {
        behaviors.push("bash-unresolved-working-directory");
      }
      if (
        !labels.some(
          (item) => item.en === UNRESOLVED_CWD_LABEL.en && item.zh === UNRESOLVED_CWD_LABEL.zh,
        )
      ) {
        labels.push(UNRESOLVED_CWD_LABEL);
      }
    }

    return { ...analysis, behaviors, labels, hardBlocked, denyTier, requiresConfirmation };
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

  protected async delegate(
    params: unknown,
    signal: AbortSignal | undefined,
    onUpdate: ToolUpdateCallback,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult> {
    if (!ctx.invokeTool) {
      this.deps.logger.log("bash: ctx.invokeTool unavailable — cannot delegate");
      return {
        content: [{ type: "text", text: "Error: native bash tool delegation unavailable in this host" }],
        details: { error: "invokeTool-unavailable" },
        isError: true,
      };
    }

    // Tool schemas guarantee an object; retain the native input unchanged so
    // OMP's async, PTY, and named-service fields reach the built-in.
    const nativeParams = params as Record<string, unknown>;
    const serviceName = typeof nativeParams.name === "string" && nativeParams.name.trim()
      ? nativeParams.name.trim()
      : undefined;
    const command = typeof nativeParams.command === "string" ? nativeParams.command : "";
    const workspaceCwd = ctx.cwd || process.cwd();
    const sessionId = sessionIdOf(ctx);
    try {
      const result = await ctx.invokeTool(nativeParams, { signal, onUpdate });
      if (serviceName && sessionId) {
        const details = result.details;
        const service = details && typeof details === "object" && "service" in details
          ? details.service
          : undefined;
        const serviceNameFromResult =
          service && typeof service === "object" && "name" in service ? service.name : undefined;
        const state =
          service && typeof service === "object" && "state" in service ? service.state : undefined;
        const terminal = ["exited", "failed", "stopped"].includes(String(state));
        if (serviceNameFromResult === serviceName) {
          if (terminal) {
            // The public service exited; retained registrations ignore owner checks.
            forgetProcService(serviceName, workspaceCwd, sessionId);
          } else {
            trackInteractiveService(
              serviceName,
              command,
              this.resolveCwd(params, ctx),
              workspaceCwd,
              sessionId,
            );
          }
        }
      }
      return result;
    } catch (error) {
      // A thrown invocation does not prove the public service exited.
      // Keep any existing registration rather than untrack a routable name.
      throw error;
    }
}
}
