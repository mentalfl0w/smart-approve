/**
 * Smart Approve — hub launch guard.
 *
 * Intercepts omp `hub` tool calls and blocks dangerous process launches
 * before they reach the host.  Only `op === "start"` calls (启动子进程) are
 * reviewed; every other op passes through untouched.  Pure logic: the class
 * never touches omp runtime objects, never reads or writes files, and never
 * makes network requests — everything is derived from the params plus the
 * session working directory.
 */

import path from "node:path";
import os from "node:os";

import { makeLabel } from "./i18n.ts";

export interface HubStartParams {
  op?: unknown;
  application?: unknown;
  args?: unknown;
  cwd?: unknown;
}

export interface HubGuardVerdict {
  block: boolean;
  reason?: { en: string; zh: string };
}

// ── Rule 1: applications that are never allowed to launch ────────────

const HARD_REJECT: Record<string, true> = {
  osascript: true,
  sudo: true,
  ssh: true,
  scp: true,
  nc: true,
  netcat: true,
  ncat: true,
  socat: true,
  telnet: true,
  openssl: true,
  curl: true,
  wget: true,
};

// ── Rule 2: interpreters whose execution flags turn args into code ────
//
// The python family collapses to "python" during normalization; node
// variants (node20, node24, ...) keep their basename and are therefore not
// treated as interpreters — only the exact names below are.

const INTERPRETERS: Record<string, true> = {
  sh: true,
  bash: true,
  zsh: true,
  dash: true,
  csh: true,
  tcsh: true,
  ksh: true,
  fish: true,
  node: true,
  bun: true,
  deno: true,
  python: true,
  ruby: true,
  perl: true,
  php: true,
  lua: true,
  tclsh: true,
  expect: true,
};

const EXEC_FLAGS: Record<string, true> = {
  "-c": true,
  "-e": true,
  "--eval": true,
  "--command": true,
  "-i": true,
};

// ── Rule 3: dangerous payloads anywhere in the joined args ────────────
//
// Matching is case-insensitive on purpose: `rm -RF`, `CHMOD`, `DD if=...`
// all resolve to the same destructive action.

const DANGEROUS_ARG_PATTERNS: RegExp[] = [
  /\brm\s+(?:-rf\b|-r\s+-f\b)/i, // rm -rf / rm -Rf / rm -r -f
  /\bchmod\b/i,
  /\bchown\b/i,
  /\bdd\b[\s\S]*\bof=/i, // dd ... of= (raw device write)
  /\bmkfs/i, // mkfs / mkfs.ext4 / ...
  /\bshutdown\b/i,
  /\breboot\b/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}/i, // fork bomb :(){ :|:& };:
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/etc\/sudoers/i,
  />\s*\/dev\/sd/i, // > /dev/sd* block device
  />\s*\/dev\/nvme/i, // > /dev/nvme* block device
];

// ── Rule 4: sensitive working directories ────────────────────────────

const SENSITIVE_DIRS: string[] = [
  "/etc",
  "/usr",
  "/var",
  "/bin",
  "/sbin",
  "/boot",
  "/Library",
  "/System",
  "/private",
];

/** Home-relative sensitive dirs; matched against the expanded home path. */
const SENSITIVE_HOME_DIRS: string[] = [".ssh", ".gnupg"];

// ── Normalization helpers ────────────────────────────────────────────

const PYTHON_ALIASES: Record<string, true> = {
  python: true,
  python2: true,
  python3: true,
  pypy: true,
  pypy3: true,
};

/** basename, lowercase; python-family executables collapse to "python". */
function normalizeApplication(application: string): string {
  const base = path.basename(application).toLowerCase();
  return PYTHON_ALIASES[base] === true ? "python" : base;
}

/** Non-array args normalize to [] so nothing matches. */
function normalizeArgs(args: unknown): string[] {
  if (!Array.isArray(args)) return [];
  return args.map((arg) => String(arg));
}

/** Expand a leading ~, then resolve; non-string / empty values become undefined. */
function normalizeCwd(cwd: unknown): string | undefined {
  if (typeof cwd !== "string" || cwd.trim() === "") return undefined;
  let value = cwd.trim();
  if (value === "~") {
    value = os.homedir();
  } else if (value.startsWith("~/")) {
    value = path.join(os.homedir(), value.slice(2));
  }
  return path.resolve(value);
}

/** True when resolved equals base or lives strictly below it (as a path prefix). */
function isUnder(resolved: string, base: string): boolean {
  const prefix = base === path.sep ? base : base + path.sep;
  return resolved === base || resolved.startsWith(prefix);
}

/** True when resolved is (or lives under) a sensitive directory. */
function isSensitiveDir(resolved: string): boolean {
  const home = os.homedir();
  const prefixes = [
    ...SENSITIVE_DIRS,
    ...SENSITIVE_HOME_DIRS.map((d) => path.join(home, d)),
  ];
  return prefixes.some((p) => resolved === p || resolved.startsWith(p + path.sep));
}

// ── Guard ────────────────────────────────────────────────────────────

/**
 * Reviews a `hub` tool_call.  Only `op === "start"` launches processes;
 * every other op is allowed.  Start calls are checked in order:
 *   1. hard-rejected applications,
 *   2. interpreters invoked with an execution flag,
 *   3. dangerous payloads anywhere in the args,
 *   4. sensitive working directories outside the session cwd.
 */
export class HubLaunchGuard {
  evaluate(params: HubStartParams, sessionCwd: string): HubGuardVerdict {
    if (params.op !== "start") {
      return { block: false };
    }

    const application = params.application;
    if (typeof application !== "string" || application.trim() === "") {
      return { block: false };
    }

    const app = normalizeApplication(application);
    const args = normalizeArgs(params.args);

    // Rule 1: hard reject set.
    if (HARD_REJECT[app] === true) {
      return {
        block: true,
        reason: makeLabel(
          `Blocked hub start: ${app} is not allowed`,
          `已拦截 hub 启动：不允许的应用 ${app}`,
        ),
      };
    }

    // Rule 2: interpreter + execution flag.
    if (INTERPRETERS[app] === true && args.some((arg) => EXEC_FLAGS[arg] === true)) {
      return {
        block: true,
        reason: makeLabel(
          "Blocked hub start: interpreter with execution flag",
          "已拦截 hub 启动：解释器带执行标志",
        ),
      };
    }

    // Rule 3: dangerous payload in the joined args.
    if (DANGEROUS_ARG_PATTERNS.some((re) => re.test(args.join(" ")))) {
      return {
        block: true,
        reason: makeLabel(
          "Blocked hub start: dangerous arguments",
          "已拦截 hub 启动：参数含危险内容",
        ),
      };
    }

    // Rule 4: sensitive working directory outside the session cwd.
    const resolvedCwd = normalizeCwd(params.cwd);
    if (
      resolvedCwd !== undefined &&
      isSensitiveDir(resolvedCwd) &&
      !isUnder(resolvedCwd, path.resolve(sessionCwd))
    ) {
      return {
        block: true,
        reason: makeLabel(
          "Blocked hub start: sensitive working directory",
          "已拦截 hub 启动：敏感工作目录",
        ),
      };
    }

    return { block: false };
  }
}
