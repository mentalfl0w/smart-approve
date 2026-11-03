/**
 * Smart Approve — eval tool code behavior analysis.
 *
 * Pure, execution-free analysis of eval-tool code snippets (JS/TS, Python,
 * plus shell commands embedded in strings/templates).  Used by the approval
 * gate to decide whether a snippet intends to spawn a subprocess or invoke
 * system commands.
 *
 * Precision is valued over recall: comments are always scrubbed, and
 * spawn-API detection also scrubs string literals.  Destructive payload and
 * launch checks keep string contents because that is where command text
 * lives; bare `exec(` / `spawn(` / `fork(` calls only count when the code
 * actually imports node:child_process.
 */

import type { DangerAnalysis } from "./types.ts";
import { analyzeCommand, isSensitiveWorkingDirectory } from "./behaviors.ts";
import { makeLabel } from "./i18n.ts";
import { resolveFilesystemPathCandidates } from "./paths.ts";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ── Behavior catalog ─────────────────────────────────────────────────

const BEHAVIORS: Record<string, { en: string; zh: string }> = {
  "eval-process-spawn": makeLabel(
    "Spawns a subprocess or invokes system commands",
    "代码中启动子进程/调用系统命令",
  ),
  "eval-dangerous-payload": makeLabel(
    "Subprocess invocation with dangerous payload",
    "子进程调用携带危险载荷",
  ),
  "eval-risky-process": makeLabel("Spawns a high-risk executable or uses dangerous process arguments", "启动高风险程序或带有危险进程参数"),
  "eval-sensitive-working-directory": makeLabel(
    "Changes into a sensitive system directory",
    "切换到敏感系统目录",
  ),
  "eval-unresolved-shell-cwd": makeLabel(
    "Shell command changes to a directory that cannot be resolved statically",
    "Shell 命令切换到无法静态确定的目录",
  ),
  "eval-external-source": makeLabel(
    "Runs or loads external source that cannot be inspected statically",
    "执行或加载无法静态检查的外部源码",
  ),
};

// ── Comment / string scrubbing ───────────────────────────────────────

/**
 * Return `code` with comments (and, unless `keepStrings`, string/template
 * literals) replaced by spaces.  Newlines are preserved so patterns can
 * never span unrelated lines, and replaced characters keep their width so
 * token boundaries stay intact.
 *
 * `#` is only treated as a comment start when it is not preceded by a word
 * character or `.`, which keeps JS private-field syntax (`this.#x`) intact.
 */
function scrub(code: string, keepStrings: boolean): string {
  const out: string[] = [];
  let i = 0;
  const n = code.length;

  while (i < n) {
    const c = code[i];
    const next = code[i + 1];

    if (c === "/" && next === "/") {
      while (i < n && code[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    if (c === "/" && next === "*") {
      out.push("  ");
      i += 2;
      while (i < n) {
        if (code[i] === "*" && code[i + 1] === "/") {
          out.push("  ");
          i += 2;
          break;
        }
        out.push(code[i] === "\n" ? "\n" : " ");
        i++;
      }
      continue;
    }
    if (c === "#" && !/[\w]/.test(code[i - 1] ?? "") && code[i - 1] !== ".") {
      while (i < n && code[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      const quote = c;
      out.push(keepStrings ? quote : " ");
      i++;
      while (i < n) {
        if (code[i] === "\\") {
          if (keepStrings) {
            out.push(code[i], code[i + 1] ?? " ");
          } else {
            out.push("  ");
          }
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          out.push(keepStrings ? quote : " ");
          i++;
          break;
        }
        if (keepStrings) {
          out.push(code[i]);
        } else {
          out.push(code[i] === "\n" ? "\n" : " ");
        }
        i++;
      }
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join("");
}

export interface EvalWriteTargets {
  paths: string[];
  dynamic: boolean;
  cwdPaths: string[];
  cwdDynamic: boolean;
}

/** OMP magic syntax belongs to Python cells only. */
function isPythonLanguage(language?: string): boolean {
  return typeof language === "string" && /^py(?:thon)?\d*(?:\.\d+)*$/i.test(language.trim());
}

interface PythonMagicScan {
  codeText: string;
  maskedCode: string;
  commands: string[];
  spawnIntent: boolean;
  writePaths: string[];
  writeDynamic: boolean;
  cwdOperations: Array<{ offset: number; target: string }>;
  externalSource: boolean;
}

function stripPythonMagicTarget(value: string): string {
  let target = value.trim();
  target = target.replace(/^(?:-a|--append)\s+/, "");
  if (target.length >= 2) {
    const quote = target[0];
    if ((quote === "\"" || quote === "'") && target[target.length - 1] === quote) {
      target = target.slice(1, -1);
    }
  }
  return target;
}

/** OMP's Python runner folds backslash continuations before executing magics. */
function foldShellContinuations(value: string): string {
  return value.replace(/\\\r?\n/g, " ");
}

/**
 * Scan OMP Python-cell magics.  Detection uses the comment/string-scrubbed
 * view so text inside literals is not mistaken for a magic; arguments and
 * shell bodies come from the raw source.  `%%writefile` bodies are content,
 * not code, so they are excluded from shell checks.
 */
function scanPythonMagics(
  source: string,
  executable: string,
  withStrings: string,
): PythonMagicScan {
  const scan: PythonMagicScan = {
    codeText: "",
    maskedCode: "",
    commands: [],
    spawnIntent: false,
    writePaths: [],
    writeDynamic: false,
    cwdOperations: [],
    externalSource: false,
  };
  const sourceLines = source.split("\n");
  const executableLines = executable.split("\n");
  const readableLines = withStrings.split("\n");
  const maskedLines = [...executableLines];
  const codeLines: string[] = [];
  const lineOffsets: number[] = [];
  let runningOffset = 0;
  for (const line of sourceLines) {
    lineOffsets.push(runningOffset);
    runningOffset += line.length + 1;
  }
  const maskLine = (index: number): void => {
    maskedLines[index] = " ".repeat(executableLines[index]?.length ?? 0);
  };

  for (let index = 0; index < executableLines.length; index++) {
    const line = executableLines[index];
    const original = sourceLines[index] ?? "";
    const readable = readableLines[index] ?? "";

    if (/^\s*%%bash\b/.test(line)) {
      scan.spawnIntent = true;
      const script = foldShellContinuations(
        sourceLines.slice(index + 1).join("\n"),
      ).trim();
      if (script) scan.commands.push(script);
      for (let cursor = index; cursor < executableLines.length; cursor++) maskLine(cursor);
      break;
    }

    const writefile = /^\s*%%writefile\b/.exec(line);
    if (writefile) {
      const target = stripPythonMagicTarget(readable.slice(writefile[0].length));
      if (target) scan.writePaths.push(target);
      else scan.writeDynamic = true;
      for (let cursor = index; cursor < executableLines.length; cursor++) maskLine(cursor);
      break;
    }

    if (/^\s*%(?:run|load)\b/.test(line)) {
      scan.externalSource = true;
      maskLine(index);
      continue;
    }

    const cd = /^\s*%cd\b/.exec(line);
    if (cd) {
      const target = stripPythonMagicTarget(readable.slice(cd[0].length));
      scan.cwdOperations.push({ offset: lineOffsets[index] ?? 0, target: target || "~" });
      maskLine(index);
      continue;
    }

    if (/^\s*%(?:pip|bun)\b/.test(line)) {
      maskLine(index);
      continue;
    }

    const assignment = /^\s*[A-Za-z_]\w*\s*=\s*!(?!=)/.exec(line);
    const escape = assignment ?? /^\s*!(?!=)/.exec(line);
    if (escape) {
      const bang = escape[0].lastIndexOf("!");
      let commandLine = index;
      let command = original.slice(escape.index + bang + 1).trim();
      while (
        command.replace(/\r$/, "").endsWith("\\") &&
        commandLine + 1 < sourceLines.length
      ) {
        command = command.replace(/\r$/, "");
        commandLine++;
        maskLine(commandLine);
        const nextLine = sourceLines[commandLine] ?? "";
        command = `${command.slice(0, -1)} ${nextLine.replace(/\r$/, "")}`;
      }
      command = foldShellContinuations(command).trim();
      if (command) {
        scan.spawnIntent = true;
        scan.commands.push(command);
      }
      maskLine(index);
      index = commandLine;
      continue;
    }

    codeLines.push(readableLines[index] ?? "");
  }

  scan.codeText = codeLines.join("\n");
  scan.maskedCode = maskedLines.join("\n");
  return scan;
}

interface LeadingShellCwd {
  target?: string;
  unresolved?: boolean;
}

/** Expand only HOME forms that are known without running the shell. */
function expandShellCwdLiteral(
  raw: string,
  expandTilde: boolean,
  expandVariables: boolean,
): string | undefined {
  let value = raw;
  if (expandTilde) {
    if (value === "~") value = process.env.HOME || os.homedir();
    else if (value.startsWith("~/")) {
      value = path.join(process.env.HOME || os.homedir(), value.slice(2));
    } else if (value.startsWith("~")) {
      return undefined;
    }
  }
  if (expandVariables) {
    const placeholder = "\0HOME\0";
    value = value
      .replace(/\$\{HOME\}/g, placeholder)
      .replace(/\$HOME(?![A-Za-z0-9_])/g, placeholder);
    if (/[$`]/.test(value)) return undefined;
    value = value.split(placeholder).join(process.env.HOME || os.homedir());
  }
  if (!value || value === "-") return undefined;
  return value;
}

/**
 * Parse a leading `cd <literal>` in a shell escape or `%%bash` body,
 * aligned with the Bash gate's leading-cd semantics.  Only the first cd
 * target is considered; later shell operations run inside it.
 */
function parseLeadingShellCwd(command: string): LeadingShellCwd {
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
  let index = start + match[0].length;
  const skipWhitespace = (): void => {
    while (index < command.length && /\s/.test(command[index])) index++;
  };
  skipWhitespace();

  const home = process.env.HOME || os.homedir();
  if (index >= command.length || command.startsWith("&&", index)) return { target: home };
  if (
    command.startsWith("--", index) &&
    (index + 2 >= command.length || /\s/.test(command[index + 2]))
  ) {
    index += 2;
    skipWhitespace();
    if (index >= command.length) return { target: home };
  }

  let raw: string;
  let expandTilde = true;
  let expandVariables = true;
  const quote = command[index];
  if (quote === "'") {
    const end = command.indexOf("'", index + 1);
    if (end === -1) return { unresolved: true };
    raw = command.slice(index + 1, end);
    expandTilde = false;
    expandVariables = false;
  } else if (quote === "\"") {
    let value = "";
    let cursor = index + 1;
    while (cursor < command.length) {
      const ch = command[cursor];
      if (ch === "\\") {
        const next = command[cursor + 1];
        if (next === undefined) return { unresolved: true };
        if (next === "$" || next === "`" || next === "\"" || next === "\\") value += next;
        else value += ch;
        cursor += 2;
        continue;
      }
      if (ch === "\"") break;
      value += ch;
      cursor++;
    }
    if (cursor >= command.length) return { unresolved: true };
    raw = value;
    expandTilde = false;
  } else {
    let value = "";
    let cursor = index;
    let escapedDynamic = false;
    let literalTilde = false;
    while (cursor < command.length) {
      const ch = command[cursor];
      if (/\s/.test(ch) || ch === "&" || ch === ";" || ch === "|" || ch === "<" || ch === ">") break;
      if (ch === "'" || ch === "\"") return { unresolved: true };
      if (ch === "\\") {
        const next = command[cursor + 1];
        if (next === undefined) return { unresolved: true };
        if (next === "$" || next === "`") escapedDynamic = true;
        else if (value === "" && next === "~") literalTilde = true;
        value += next;
        cursor += 2;
        continue;
      }
      value += ch;
      cursor++;
    }
    if (!value) return { unresolved: true };
    if (escapedDynamic) return { unresolved: true };
    if (/[*?\[\]{}]/.test(value)) return { unresolved: true };
    raw = value;
    expandTilde = !literalTilde;
  }

  const target = expandShellCwdLiteral(raw, expandTilde, expandVariables);
  if (target === undefined) return { unresolved: true };
  return { target };
}

/** Resolve a literal cd target and return it only when it is an existing directory. */
function existingDirectory(target: string, baseCwd: string): string | undefined {
  const candidates = resolveFilesystemPathCandidates(target, baseCwd);
  const resolved = candidates[candidates.length - 1];
  if (!resolved) return undefined;
  try {
    return fs.statSync(resolved).isDirectory() ? resolved : undefined;
  } catch {
    return undefined;
  }
}

interface QuotedArgument {
  value: string;
  end: number;
}

function readQuotedArgument(source: string, start: number): QuotedArgument | undefined {
  let index = start;
  while (/\s/.test(source[index] ?? "")) index++;
  const quote = source[index];
  if (quote !== "'" && quote !== "\"") return undefined;
  const valueStart = ++index;
  while (index < source.length && source[index] !== quote) {
    if (source[index] === "\\") return undefined;
    index++;
  }
  if (index >= source.length) return undefined;
  return { value: source.slice(valueStart, index), end: index + 1 };
}

function findArgumentComma(source: string, start: number): number {
  let quote: string | undefined;
  let depth = 0;
  for (let index = start; index < source.length; index++) {
    const ch = source[index];
    if (ch === "\\") {
      index++;
      continue;
    }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return -1;
      depth--;
    } else if (ch === "," && depth === 0) {
      return index;
    }
  }
  return -1;
}

const EVAL_WRITE_CALLS: Array<{ pattern: RegExp; mode: "write" | "open" }> = [
  { pattern: /\b(?:globalThis\.)?write\s*\(/g, mode: "write" },
  { pattern: /\b(?:[A-Za-z_$][\w$]*\.)*writeFile(?:Sync)?\s*\(/g, mode: "write" },
  { pattern: /\bopen\s*\(/g, mode: "open" },
];

const EVAL_CHDIR_CALL = /\b(?:(?:process|os|Dir)\.)?chdir\s*\(/g;

// ── Task Group static proc cancellation ──────────────────────────────
//
// Task Group cancels a Pool through the ordinary public write tool:
//   const result = await tool.write({ path: "proc://" + TG_GROUP + "/kill" });
// That path is dynamic by construction, so the generic write collector would
// otherwise require confirmation on every Pool cancel.  Recognize only the
// exact compiled shape: a `tool.write` call whose object contains only `path`,
// whose expression is a concatenation of literals and same-source string
// consts, whose `TG_PROTOCOL` is the Task Group wire protocol, and whose
// `TG_GROUP` is a newGroupId() value explicitly spliced into the target.

/** Tool-description marker Task Group may inspect on the registered Eval tool. */
export const TASK_GROUP_PROC_CANCEL_MARKER = "omp-task-group-pool-proc-cancel:v1";

/** Wire protocol embedded in every compiled Task Group eval program. */
const TASK_GROUP_PROTOCOL = "omp-task-group/eval-result-v1";

/** `newGroupId()` output: `tg` followed only by lowercase base-36 characters. */
const TASK_GROUP_ID = /^tg[a-z0-9]+$/;

const TASK_GROUP_PROC_WRITE = /\btool\s*\.\s*write\s*\(/g;
const STATIC_IDENTIFIER = /[A-Za-z_$][\w$]*/y;
const MAX_STATIC_EXPRESSION_DEPTH = 32;

interface StaticStringView {
  /** Comments removed, string literals preserved: expression parsing input. */
  text: string;
  /** Comments and string literals removed: declaration syntax discovery. */
  code: string;
}

interface StaticStringResolution {
  value: string;
  identifiers: Set<string>;
  end: number;
}

function skipStaticWhitespace(text: string, index: number): number {
  while (index < text.length && /\s/.test(text[index])) index++;
  return index;
}

/** Read a single- or double-quoted literal without escapes (generated shape). */
function readStaticString(
  text: string,
  start: number,
): { value: string; end: number } | undefined {
  const quote = text[start];
  if (quote !== "'" && quote !== "\"") return undefined;
  let index = start + 1;
  let value = "";
  while (index < text.length) {
    const character = text[index];
    if (character === "\\" || character === "\n" || character === "\r") return undefined;
    if (character === quote) return { value, end: index + 1 };
    value += character;
    index++;
  }
  return undefined;
}

function readStaticIdentifier(
  text: string,
  start: number,
): { name: string; end: number } | undefined {
  STATIC_IDENTIFIER.lastIndex = start;
  const match = STATIC_IDENTIFIER.exec(text);
  if (!match) return undefined;
  return { name: match[0], end: start + match[0].length };
}

function escapeStaticRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Return the initializer start only for a unique, never-reassigned `const`.
 * A second declaration, a `let`/`var` binding, or any assignment makes the
 * value non-static for this recognition.
 */
function hasShadowingBinding(name: string, code: string): boolean {
  const escaped = escapeStaticRegExp(name);
  const bindings = [
    new RegExp(`\\b(?:let|var)\\s+${escaped}\\b`),
    new RegExp(`\\b(?:function|class)\\s+${escaped}\\b`),
    new RegExp(`\\bfunction(?:\\s+[A-Za-z_$][\\w$]*)?\\s*\\([^)]*\\b${escaped}\\b[^)]*\\)`),
    new RegExp(`\\b(?:async\\s+)?function\\s*\\*\\s*(?:[A-Za-z_$][\\w$]*)?\\s*\\([^)]*\\b${escaped}\\b[^)]*\\)`),
    new RegExp(`\\([^)]*\\b${escaped}\\b[^)]*\\)\\s*=>`),
    new RegExp(`\\b${escaped}\\s*=>`),
    new RegExp(`\\bcatch\\s*\\([^)]*\\b${escaped}\\b[^)]*\\)`),
    new RegExp(`\\bfor\\s*\\(\\s*(?:const|let|var)\\s+${escaped}\\b`),
    new RegExp(`\\b(?:const|let|var)\\s*[\\[{][^;]*\\b${escaped}\\b`),
    new RegExp(`\\bimport\\s*\\{[^}]*\\b${escaped}\\b`),
    new RegExp(`\\bimport\\s+${escaped}\\b`),
  ];
  if (bindings.some((pattern) => pattern.test(code))) return true;

  const methodParameters =
    /(?:^|[;{},\n])\s*(?:(?:static|public|private|protected|override)\s+)*(?:async\s+)?(?:(?:get|set)\s+)?\*?\s*([A-Za-z_$][\w$]*|\[[^\]\n]+\])\s*\(([^)]*)\)\s*(?::[^{}]+)?\{/gm;
  const controlWords = new Set(["if", "for", "while", "switch", "catch", "with"]);
  let method: RegExpExecArray | null;
  while ((method = methodParameters.exec(code)) !== null) {
    if (
      !controlWords.has(method[1] ?? "") &&
      new RegExp(`\\b${escaped}\\b`).test(method[2] ?? "")
    ) {
      return true;
    }
  }
  return false;
}

function findStaticConst(name: string, view: StaticStringView): { start: number } | undefined {
  const escaped = escapeStaticRegExp(name);
  const declarations = [...view.code.matchAll(new RegExp(`\\bconst\\s+${escaped}\\s*=`, "g"))];
  if (declarations.length !== 1 || hasShadowingBinding(name, view.code)) return undefined;
  const declaration = declarations[0];
  // Compiled Task Group constants live in the prelude. Refuse nested/local
  // declarations so the call cannot resolve to a different runtime binding.
  if (/[{}]/.test(view.code.slice(0, declaration.index))) return undefined;
  const assignments = [...view.code.matchAll(new RegExp(`\\b${escaped}\\s*=(?!=)`, "g"))];
  if (assignments.length !== 1) return undefined;
  return { start: declaration.index + declaration[0].length };
}

function resolveStaticExpression(
  view: StaticStringView,
  index: number,
  stack: string[],
  depth: number,
): StaticStringResolution | undefined {
  if (depth > MAX_STATIC_EXPRESSION_DEPTH) return undefined;
  let cursor = skipStaticWhitespace(view.text, index);
  let value = "";
  const identifiers = new Set<string>();
  let expectAtom = true;

  while (true) {
    cursor = skipStaticWhitespace(view.text, cursor);
    if (expectAtom) {
      const atom = readStaticAtom(view, cursor, stack, depth);
      if (!atom) return undefined;
      value += atom.value;
      for (const identifier of atom.identifiers) identifiers.add(identifier);
      cursor = atom.end;
      expectAtom = false;
      continue;
    }
    if (view.text[cursor] === "+") {
      cursor++;
      expectAtom = true;
      continue;
    }
    break;
  }

  if (expectAtom) return undefined;
  return { value, identifiers, end: cursor };
}

function readStaticAtom(
  view: StaticStringView,
  index: number,
  stack: string[],
  depth: number,
): StaticStringResolution | undefined {
  const literal = readStaticString(view.text, index);
  if (literal) {
    return { value: literal.value, identifiers: new Set(), end: literal.end };
  }

  if (view.text[index] === "(") {
    const inner = resolveStaticExpression(view, index + 1, stack, depth + 1);
    if (!inner) return undefined;
    const end = skipStaticWhitespace(view.text, inner.end);
    if (view.text[end] !== ")") return undefined;
    return { value: inner.value, identifiers: inner.identifiers, end: end + 1 };
  }

  const identifier = readStaticIdentifier(view.text, index);
  if (!identifier) return undefined;
  const resolved = resolveStaticConst(identifier.name, view, stack, depth + 1);
  if (!resolved) return undefined;
  const identifiers = new Set(resolved.identifiers);
  identifiers.add(identifier.name);
  return { value: resolved.value, identifiers, end: identifier.end };
}

function resolveStaticConst(
  name: string,
  view: StaticStringView,
  stack: string[],
  depth: number,
): StaticStringResolution | undefined {
  if (stack.includes(name) || depth > MAX_STATIC_EXPRESSION_DEPTH) return undefined;
  const declaration = findStaticConst(name, view);
  if (!declaration) return undefined;
  const expression = resolveStaticExpression(view, declaration.start, [...stack, name], depth + 1);
  if (!expression) return undefined;
  const end = skipStaticWhitespace(view.text, expression.end);
  if (view.text[end] !== ";") return undefined;
  return { value: expression.value, identifiers: expression.identifiers, end: end + 1 };
}

/** Dynamic, shadowed, or runtime-generated `tool` bindings invalidate the shape. */
function isShadowedTaskGroupTool(code: string): boolean {
  return (
    /\bwith\s*\(/.test(code) ||
    /\b(?:eval|Function)\s*\(/.test(code) ||
    hasShadowingBinding("tool", code) ||
    /\btool\s*=(?!=)/.test(code) ||
    /\btool\s*(?:\.\s*write|\[\s*["']write["']\s*\])\s*(?:=(?!=)|\+=|-=|\*=|\/=)/.test(code) ||
    /\b(?:Object\.assign|Object\.defineProperty|Reflect\.set)\s*\(\s*tool\b/.test(code)
  );
}

/**
 * Match `tool.write({ path: <static concat> })` at `open` and verify the
 * Task Group fingerprint.  The object must contain only `path`; the target
 * must resolve to `proc://<TG_GROUP>/kill`; TG_GROUP must be an explicit
 * operand whose unique static const matches a Task Group id, and TG_PROTOCOL
 * must be the exact Task Group wire protocol.
 */
function isTaskGroupProcCancelAt(view: StaticStringView, open: number): boolean {
  let cursor = skipStaticWhitespace(view.text, open + 1);
  if (view.text[cursor] !== "{") return false;
  cursor = skipStaticWhitespace(view.text, cursor + 1);

  const key = readStaticIdentifier(view.text, cursor);
  if (!key || key.name !== "path") return false;
  cursor = skipStaticWhitespace(view.text, key.end);
  if (view.text[cursor] !== ":") return false;

  const target = resolveStaticExpression(view, cursor + 1, [], 0);
  if (!target) return false;
  cursor = skipStaticWhitespace(view.text, target.end);
  if (view.text[cursor] === ",") cursor = skipStaticWhitespace(view.text, cursor + 1);
  if (view.text[cursor] !== "}") return false;
  cursor = skipStaticWhitespace(view.text, cursor + 1);
  if (view.text[cursor] !== ")") return false;

  if (!target.identifiers.has("TG_GROUP")) return false;
  const protocol = resolveStaticConst("TG_PROTOCOL", view, [], 0);
  if (!protocol || protocol.value !== TASK_GROUP_PROTOCOL) return false;
  const group = resolveStaticConst("TG_GROUP", view, [], 0);
  if (!group || !TASK_GROUP_ID.test(group.value)) return false;
  return target.value === `proc://${group.value}/kill`;
}

/** Offsets of recognized Task Group pool-cancel `tool.write` calls. */
function findTaskGroupProcCancelCalls(source: string, executable: string): Set<number> {
  const offsets = new Set<number>();
  if (isShadowedTaskGroupTool(executable)) return offsets;

  const candidates: number[] = [];
  TASK_GROUP_PROC_WRITE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TASK_GROUP_PROC_WRITE.exec(executable)) !== null) {
    const start = match.index;
    if (start > 0 && /[\w$.]/.test(executable[start - 1])) continue;
    candidates.push(start + match[0].lastIndexOf("("));
  }
  if (candidates.length === 0) return offsets;

  const view: StaticStringView = { text: scrub(source, true), code: executable };
  for (const open of candidates) {
    if (isTaskGroupProcCancelAt(view, open)) offsets.add(open);
  }
  return offsets;
}

/** Static file-write targets from Eval helpers, Python magics, and common file APIs. */
export function extractEvalWriteTargets(code: string, language?: string): EvalWriteTargets {
  const source = String(code ?? "");
  const executable = scrub(source, false);
  const pythonScan = isPythonLanguage(language)
    ? scanPythonMagics(source, executable, scrub(source, true))
    : undefined;
  const paths = new Set<string>();
  const cwdOperations: Array<{ offset: number; target: string }> = [];
  let cwdDynamic = false;
  let dynamic = false;
  const scanText = pythonScan ? pythonScan.maskedCode : executable;
  // Task Group eval programs are JavaScript; Python cells keep current behavior.
  const staticProcCancelCalls = pythonScan
    ? undefined
    : findTaskGroupProcCancelCalls(source, executable);

  for (const call of EVAL_WRITE_CALLS) {
    call.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = call.pattern.exec(scanText)) !== null) {
      const open = match.index + match[0].lastIndexOf("(");
      if (call.mode === "write" && staticProcCancelCalls?.has(open)) continue;
      const first = readQuotedArgument(source, open + 1);
      if (call.mode === "open") {
        const comma = findArgumentComma(source, open + 1);
        if (comma < 0) continue;
        const mode = readQuotedArgument(source, comma + 1);
        if (mode && !/[wax+]/.test(mode.value)) continue;
        if (!mode) {
          dynamic = true;
          continue;
        }
      }
      if (first) paths.add(first.value);
      else dynamic = true;
    }
  }

  EVAL_CHDIR_CALL.lastIndex = 0;
  let chdir: RegExpExecArray | null;
  while ((chdir = EVAL_CHDIR_CALL.exec(scanText)) !== null) {
    const open = chdir.index + chdir[0].lastIndexOf("(");
    const target = readQuotedArgument(source, open + 1);
    if (target) cwdOperations.push({ offset: chdir.index, target: target.value });
    else cwdDynamic = true;
  }

  if (pythonScan) {
    for (const target of pythonScan.writePaths) paths.add(target);
    if (pythonScan.writeDynamic) dynamic = true;
    cwdOperations.push(...pythonScan.cwdOperations);
  }

  cwdOperations.sort((a, b) => a.offset - b.offset);
  return {
    paths: [...paths],
    dynamic,
    cwdPaths: cwdOperations.map((operation) => operation.target),
    cwdDynamic,
  };
}

// ── Spawn-intent patterns ────────────────────────────────────────────

/** Import of the Node child_process module (require, static ESM, or dynamic ESM). */
const CHILD_PROCESS_IMPORT =
  /(?:require\(\s*["'](?:node:)?child_process["']\s*\)|(?:from\s+|import\s*\()\s*["'](?:node:)?child_process["'])/;

/** Python multiprocessing import, used to recognize bare `Process(...)`. */
const MULTIPROCESSING_IMPORT =
  /(?:from\s+multiprocessing\s+import\s+[^;\n]*\bProcess\b|import\s+multiprocessing\b)/;

/** Bun.$ template-tag / call shell execution (needs string content). */
const BUN_DOLLAR = /Bun\.\$\s*(?:`|\()/;

/** OMP magic cells that hand the cell to a package manager. */
const PACKAGE_MANAGER_MAGIC = /(?:^|\n)\s*%(?:pip\s+install|bun\s+add)\b/;

/** Full package-manager directive lines, stripped before shell-command
 *  checks so a package specifier like `curl` is not read as an executable. */
const MAGIC_DIRECTIVE = /^[ \t]*%(?:pip|bun)\b[^\n]*$/gm;

/**
 * Unambiguous spawn APIs, common Python process APIs, and OMP package-manager
 * magic cells, matched on comment+string-scrubbed code.  execSync / execFile /
 * spawnSync exist only in node:child_process, so no import context is required
 * for them.
 */
const SPAWN_PATTERNS: RegExp[] = [
  PACKAGE_MANAGER_MAGIC,
  /Bun\.spawn(?:Sync)?\b/,
  /Bun\.shell\b/,
  /(?:^|[^\w$])execSync\s*\(/,
  /(?:^|[^\w$])execFile(?:Sync)?\s*\(/,
  /(?:^|[^\w$])spawnSync\s*\(/,
  /subprocess\.(?:run|Popen|call|check_call|check_output|getoutput|getstatusoutput)\b/,
  /asyncio\.create_subprocess_(?:exec|shell)\s*\(/,
  /os\.(?:system|popen)\s*\(/,
  /os\.(?:exec|spawn)[a-z]*\s*\(/,
  /os\.(?:fork|forkpty)\s*\(/,
  /(?:^|[^\w$])os\.posix_spawnp?\s*\(/,
  /(?:^|[^\w$])multiprocessing\.Process\s*\(/,
  /(?:^|[^\w$])Popen\s*\(/,
  /shell\s*=\s*True\b/,
  /(?:^|[^\w.])import\s+subprocess\b/,
  /from\s+subprocess\s+import\b/,
  /(?:__import__|importlib\.import_module)\s*\(\s*["']subprocess["']/,
];

/** exec / spawn / fork — only dangerous within a child_process context. */
const BARE_EXEC_FAMILY = /(?:^|[^\w$])(?:exec|spawn|fork)\s*\(/;

// ── Dangerous-payload patterns ───────────────────────────────────────
//
// These match on comment-scrubbed code with strings kept: the payloads
// live inside the command strings/templates that spawn APIs receive.

/** rm -rf on /, ~ or $HOME (recursive delete of root/home). */
const RM_RF_ROOT = /(?:^|[^\w$])rm\s+-(?:rf|fr)\s+(?:\/|~|\$HOME\b|\$\{HOME\})/;

/** Classic fork bomb `:(){ :|:& };:` (also tolerant of spaces). */
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

/** Infinite `while true; do ... &` background loop. */
const WHILE_TRUE_FORK = /while\s+true\s*;\s*do[\s\S]{0,100}?&(?:\s|$)/;

/** curl/wget fetched script piped straight into sh/bash. */
const CURL_PIPE_SHELL =
  /(?:^|[^\w$])(?:curl|wget)\b[^|\n]{0,200}?\|\s*(?:sudo\s+)?(?:sh|bash)\b/;

/** dd writing to a raw /dev device (excluding harmless /dev/null). */
const DD_BLOCK_DEVICE =
  /(?:^|[^\w$])dd\b[^;\n]{0,100}?of=\/dev(?!\/?null)(?![A-Za-z0-9_])/;

/** mkfs / mkfs.* filesystem formatting. */
const MKFS = /(?:^|[^\w$])mkfs(?:\.[a-z0-9]+)?\b/;

/** Shell redirection into a system-sensitive /etc file. */
const SENSITIVE_FILE_WRITE = /(?:>>|>)\s*\/etc\/(?:passwd|shadow|sudoers|hosts)\b/;

/** Shell redirection into a raw block device (matches the Bash device list). */
const BLOCK_DEVICE_WRITE =
  /(?:>>|>)\s*\/dev\/(?:sd[a-z]\d*|nvme\d|disk\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk|mapper\/|md\d|sg\d|st\d|nst\d)/;

/** Python open(..., "w"/"a") on a system-sensitive /etc file. */
const SENSITIVE_OPEN_WRITE =
  /open\(\s*["']\/etc\/(?:passwd|shadow|sudoers|hosts)["']\s*,\s*["'][wa]/;

/** Shutdown / reboot family. */
const SHUTDOWN_CMD = /(?:^|[^\w$])(?:shutdown|reboot|halt|poweroff)\b/;

function hasDangerousPayload(code: string): boolean {
  return (
    RM_RF_ROOT.test(code) ||
    FORK_BOMB.test(code) ||
    WHILE_TRUE_FORK.test(code) ||
    CURL_PIPE_SHELL.test(code) ||
    DD_BLOCK_DEVICE.test(code) ||
    MKFS.test(code) ||
    SENSITIVE_FILE_WRITE.test(code) ||
    BLOCK_DEVICE_WRITE.test(code) ||
    SENSITIVE_OPEN_WRITE.test(code) ||
    SHUTDOWN_CMD.test(code)
  );
}

/**
 * Legacy dangerous arguments, matched across the joined argument stream.
 * The payload may appear in any argument, not only in the command head.
 */
const DANGEROUS_ARGUMENT_PATTERNS: RegExp[] = [
  /\b(?:chmod|chown)\b/i,
  /\bdd\b[^;\n]{0,100}?\bof=/i,
  /\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b/i,
  /\brm\s+--(?:recursive\s+--force|force\s+--recursive)\b/i,
  /\/etc\/(?:passwd|shadow|sudoers)\b/i,
];

function quotedArrayArgs(body: string): string[] {
  return [...body.matchAll(/["'`]([^"'`]*)["'`]/g)].map((match) => match[1]);
}

/** Split a shell command on separators while respecting quotes and escapes. */
function splitShellSegments(command: string): string[] {
  const result: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < command.length; index++) {
    const ch = command[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === ";" || ch === "|" || ch === "&" || ch === "\n" || ch === "(" || ch === ")") {
      const segment = command.slice(start, index).trim();
      if (segment) result.push(segment);
      start = index + 1;
      if ((ch === "|" || ch === "&") && command[index + 1] === ch) index++;
    }
  }

  const tail = command.slice(start).trim();
  if (tail) result.push(tail);
  return result;
}

/**
 * Literal command text for recognized spawn APIs.  Shell-string calls yield
 * their command; argv calls yield their string elements in order, so the
 * first token is the executable the host actually launches.  Non-literal
 * arguments yield no head and therefore no launch hard block.
 */
function extractSpawnCommandText(code: string, childProcessImport: boolean): string[] {
  const commands = new Set<string>();
  const addArgs = (body: string): void => {
    const args = quotedArrayArgs(body);
    if (args.length > 0) commands.add(args.join(" "));
  };

  for (const match of code.matchAll(/Bun\.\$\s*`([^`]*)`/g)) commands.add(match[1]);
  for (const match of code.matchAll(/Bun\.\$\s*\(\s*(["'])([\s\S]*?)\1/g)) commands.add(match[2]);

  const shellApis = childProcessImport ? "execSync|exec" : "execSync";
  const shellPattern = new RegExp(
    `(?:subprocess\\.(?:run|call|check_call|check_output|getoutput|getstatusoutput)|os\\.(?:system|popen)|asyncio\\.create_subprocess_(?:exec|shell)|${shellApis}|Popen)\\s*\\(\\s*(["'])([\\s\\S]*?)\\1`,
    "g",
  );
  for (const match of code.matchAll(shellPattern)) commands.add(match[2]);

  for (const match of code.matchAll(
    /(?:Bun\.spawn(?:Sync)?|Bun\.shell|subprocess\.(?:run|call|check_call|check_output|Popen)|asyncio\.create_subprocess_(?:exec|shell)|execFile(?:Sync)?|spawn(?:Sync)?)\s*\(\s*\[([^\]]*)\]/g,
  )) {
    addArgs(match[1]);
  }

  for (const match of code.matchAll(
    /(?:execFile(?:Sync)?|spawn(?:Sync)?)\s*\(\s*(["'])([\s\S]*?)\1\s*(?:,\s*\[([^\]]*)\])?/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  for (const match of code.matchAll(
    /(?:^|[^\w$])os\.exec(?:vpe|vp|ve|v)\s*\(\s*(["'])([\s\S]*?)\1\s*(?:,\s*\[([^\]]*)\])?/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  for (const match of code.matchAll(
    /(?:^|[^\w$])os\.exec(?:lpe|lp|le|l)\s*\(\s*(["'])([\s\S]*?)\1([^)]*)/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  for (const match of code.matchAll(
    /(?:^|[^\w$])os\.spawn(?:vpe|vp|ve|v)\s*\(\s*[^,]+,\s*(["'])([\s\S]*?)\1\s*(?:,\s*\[([^\]]*)\])?/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  for (const match of code.matchAll(
    /(?:^|[^\w$])os\.spawn(?:lpe|lp|le|l)\s*\(\s*[^,]+,\s*(["'])([\s\S]*?)\1([^)]*)/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  for (const match of code.matchAll(
    /(?:^|[^\w$])(?:os\.)?posix_spawnp?\s*\(\s*(["'])([\s\S]*?)\1\s*(?:,\s*\[([^\]]*)\])?/g,
  )) {
    commands.add([match[2], ...quotedArrayArgs(match[3] ?? "")].join(" "));
  }

  return [...commands];
}

// ── Composite analysis ───────────────────────────────────────────────

/**
 * Analyzes eval-tool code snippets (JS/TS, Python, embedded shell) for
 * subprocess / system-command intent and static working-directory escapes,
 * purely by text patterns.  Legacy launch shapes hard-block only when the
 * code shows spawn intent and only on the parsed command head; legacy
 * dangerous arguments are matched across the joined argument stream.  A
 * plain spawn stays reviewable.  Python shell magics add spawn intent and
 * literal shell text; `%run`/`%load` require confirmation because their
 * source cannot be inspected.  `baseCwd`/`sessionCwd` let callers apply the
 * outside-session-root exception; omit them for conservative standalone
 * checking.  Never executes the code; construction has no side effects.
 */
export class EvalCodeBehaviorAnalyzer {
  analyze(
    code: string,
    language?: string,
    baseCwd?: string,
    sessionCwd?: string,
  ): DangerAnalysis {
    const source = String(code ?? "");
    const withStrings = scrub(source, true);
    const scrubbed = scrub(source, false);
    const pythonScan = isPythonLanguage(language)
      ? scanPythonMagics(source, scrubbed, withStrings)
      : undefined;
    const base = baseCwd && baseCwd.trim() ? baseCwd : process.cwd();
    const session = sessionCwd && sessionCwd.trim()
      ? sessionCwd
      : path.join(base, ".smart-approve-standalone-session");

    const found = new Set<string>();
    const childProcessImport =
      CHILD_PROCESS_IMPORT.test(withStrings) ||
      /(?:__import__|importlib\.import_module)\s*\(\s*["']subprocess["']/.test(withStrings);
    if (childProcessImport) found.add("eval-process-spawn");
    if (BUN_DOLLAR.test(withStrings)) found.add("eval-process-spawn");

    for (const pattern of SPAWN_PATTERNS) {
      if (pattern.test(scrubbed)) found.add("eval-process-spawn");
    }
    if (childProcessImport && BARE_EXEC_FAMILY.test(scrubbed)) {
      found.add("eval-process-spawn");
    }
    if (
      MULTIPROCESSING_IMPORT.test(withStrings) &&
      /(?:^|[^\w$])Process\s*\(/.test(scrubbed)
    ) {
      found.add("eval-process-spawn");
    }
    if (pythonScan?.spawnIntent) found.add("eval-process-spawn");

    const hasProcessSpawn = found.has("eval-process-spawn");
    // Magic directives execute through the host.  Their arguments are not
    // shell text; `%%writefile` bodies are file content and `%cd`/`%run`
    // lines are handled by target extraction, so drop them from shell checks.
    const codeText = pythonScan ? pythonScan.codeText : withStrings.replace(MAGIC_DIRECTIVE, " ");
    const shellText = pythonScan && pythonScan.commands.length > 0
      ? `${codeText}\n${pythonScan.commands.join("\n")}`
      : codeText;
    const dangerousPayload = hasProcessSpawn && hasDangerousPayload(shellText);
    if (dangerousPayload) found.add("eval-dangerous-payload");

    // Launch executables/interpreters are checked on the parsed command head;
    // legacy dangerous arguments are still matched across the joined stream,
    // so `["rm", "-rf", …]` and `/etc/passwd` references keep blocking.
    const launchView = shellText.replace(/["'`]+/g, " ").replace(/\s*,\s*/g, " ");
    const launchCommands = [
      ...extractSpawnCommandText(codeText, childProcessImport),
      ...(pythonScan?.commands ?? []),
    ].flatMap(splitShellSegments);
    const riskyLaunch =
      hasProcessSpawn &&
      !dangerousPayload &&
      launchCommands.some((command) => {
        const behaviors = analyzeCommand(command).behaviors;
        return (
          behaviors.includes("high-risk-executable") ||
          behaviors.includes("interpreter-inline-execution")
        );
      });
    const riskyArguments =
      hasProcessSpawn &&
      !dangerousPayload &&
      DANGEROUS_ARGUMENT_PATTERNS.some((pattern) => pattern.test(launchView));
    if (riskyLaunch || riskyArguments) found.add("eval-risky-process");

    // Literal cwd operations are resolved in source order against the
    // effective base; the shared helper applies the outside-session-root
    // exception and compares lexical + canonical candidates.
    let currentCwd = base;
    let sensitiveCwd = false;
    for (const target of extractEvalWriteTargets(source, language).cwdPaths) {
      if (isSensitiveWorkingDirectory(target, session, currentCwd)) {
        sensitiveCwd = true;
        break;
      }
      const candidates = resolveFilesystemPathCandidates(target, currentCwd);
      if (candidates.length > 0) currentCwd = candidates[candidates.length - 1];
    }

    // A leading `cd` inside each `!cmd` or `%%bash` segment runs the
    // following shell operations in that directory even though the runtime
    // cwd is unchanged.  Track literal segments in order.
    let shellCwd: string | undefined = base;
    let shellSensitiveCwd = false;
    let shellUnresolvedCwd = false;
    for (const command of pythonScan?.commands ?? []) {
      for (const segment of splitShellSegments(command)) {
        const leading = parseLeadingShellCwd(segment);
        if (leading.unresolved) {
          shellUnresolvedCwd = true;
          shellCwd = undefined;
          continue;
        }
        if (leading.target === undefined) continue;

        const baseForTarget = shellCwd;
        if (baseForTarget === undefined && !path.isAbsolute(leading.target)) {
          // A failed or unresolved earlier cd leaves the shell cwd unknown;
          // relative targets cannot be resolved safely from here.
          shellUnresolvedCwd = true;
          continue;
        }

        const resolved = existingDirectory(leading.target, baseForTarget ?? base);
        if (!resolved) {
          shellCwd = undefined;
          shellUnresolvedCwd = true;
          continue;
        }
        if (isSensitiveWorkingDirectory(leading.target, session, baseForTarget ?? base)) {
          shellSensitiveCwd = true;
        }
        shellCwd = resolved;
      }
    }
    if (sensitiveCwd || shellSensitiveCwd) found.add("eval-sensitive-working-directory");
    if (shellUnresolvedCwd) found.add("eval-unresolved-shell-cwd");

    const requiresConfirmation =
      shellUnresolvedCwd || pythonScan?.externalSource === true;
    if (pythonScan?.externalSource) found.add("eval-external-source");

    const hardBlocked =
      dangerousPayload || riskyLaunch || riskyArguments || sensitiveCwd || shellSensitiveCwd;

    const behaviors = [...found];
    const labels = behaviors.map((behavior) => BEHAVIORS[behavior] || makeLabel(behavior, behavior));
    const analysis: DangerAnalysis = {
      behaviors,
      labels,
      hardBlocked,
      denyTier: false,
    };
    return requiresConfirmation ? { ...analysis, requiresConfirmation: true } : analysis;
  }
}
