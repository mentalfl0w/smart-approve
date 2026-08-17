/**
 * Smart Approve — eval tool code behavior analysis.
 *
 * Pure, execution-free analysis of eval-tool code snippets (JS/TS, Python,
 * plus shell commands embedded in strings/templates).  Used by the approval
 * gate to decide whether a snippet intends to spawn a subprocess or invoke
 * system commands.
 *
 * Precision is valued over recall: comments and string literals are
 * scrubbed before pattern matching, and bare `exec(` / `spawn(` / `fork(`
 * calls only count when the code actually imports node:child_process.
 */

import type { DangerAnalysis } from "./types.ts";
import { makeLabel } from "./i18n.ts";

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

// ── Spawn-intent patterns ────────────────────────────────────────────

/** Import of the Node child_process module (require or ESM). */
const CHILD_PROCESS_IMPORT =
  /(?:require\(\s*["'](?:node:)?child_process["']\s*\)|(?:from\s+|import\s*\()\s*["']node:child_process["'])/;

/** Bun.$ template-tag / call shell execution (needs string content). */
const BUN_DOLLAR = /Bun\.\$\s*(?:`|\()/;

/**
 * Unambiguous spawn APIs, matched on comment+string-scrubbed code.
 * execSync / execFile / spawnSync exist only in node:child_process, so no
 * import context is required for them.
 */
const SPAWN_PATTERNS: RegExp[] = [
  /Bun\.spawn(?:Sync)?\b/,
  /Bun\.shell\b/,
  /(?:^|[^\w$])execSync\s*\(/,
  /(?:^|[^\w$])execFile\s*\(/,
  /(?:^|[^\w$])spawnSync\s*\(/,
  /subprocess\.(?:run|Popen|call)\b/,
  /os\.(?:system|popen)\s*\(/,
  /os\.exec[a-z]*\s*\(/,
  /(?:^|[^\w$])Popen\s*\(/,
  /shell\s*=\s*True\b/,
  /(?:^|[^\w.])import\s+subprocess\b/,
  /from\s+subprocess\s+import\b/,
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
    SENSITIVE_OPEN_WRITE.test(code) ||
    SHUTDOWN_CMD.test(code)
  );
}

// ── Composite analysis ───────────────────────────────────────────────

/**
 * Analyzes eval-tool code snippets (JS/TS, Python, embedded shell) for
 * subprocess / system-command intent, purely by text patterns.  Never
 * executes the code; construction has no side effects.
 */
export class EvalCodeBehaviorAnalyzer {
  analyze(code: string): DangerAnalysis {
    const source = String(code ?? "");
    // Comments removed, string/template literals kept (command payloads
    // and module specifiers live inside strings).
    const withStrings = scrub(source, true);
    // Comments and string/template literals removed (noise reduction).
    const scrubbed = scrub(source, false);

    const found = new Set<string>();

    const childProcessImport = CHILD_PROCESS_IMPORT.test(withStrings);
    if (childProcessImport) found.add("eval-process-spawn");
    if (BUN_DOLLAR.test(withStrings)) found.add("eval-process-spawn");

    for (const pattern of SPAWN_PATTERNS) {
      if (pattern.test(scrubbed)) found.add("eval-process-spawn");
    }
    if (childProcessImport && BARE_EXEC_FAMILY.test(scrubbed)) {
      found.add("eval-process-spawn");
    }

    // The dangerous-payload behavior only exists alongside spawn intent.
    if (found.has("eval-process-spawn") && hasDangerousPayload(withStrings)) {
      found.add("eval-dangerous-payload");
    }

    const behaviors = [...found];
    const labels = behaviors.map((b) => BEHAVIORS[b] || makeLabel(b, b));
    const hardBlocked = behaviors.includes("eval-dangerous-payload");

    return { behaviors, labels, hardBlocked, denyTier: false };
  }
}
