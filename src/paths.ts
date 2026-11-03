/**
 * Smart Approve — protected-path matcher.
 *
 * Glob-based matching against sensitive file paths.  Symlink-aware:
 * resolves realpath before matching so a symlink alias can't evade a deny.
 * Encapsulated as a class so patterns can be swapped per-config without
 * recompiling the glob converter.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** Default protected path patterns. */
export const DEFAULT_PROTECTED_PATHS: string[] = [
  ".env",
  ".env.*",
  "!.env.example",          // allow .env.example
  "**/.ssh/**",
  "**/.ssh/*",
  "**/.kube/config",
  "**/.aws/credentials",
  "**/.aws/config",
  "**/.config/gh/hosts.yml",
  "**/.config/gcloud/**",
  "**/.git-credentials",
  "**/.netrc",
  "**/.npmrc",
  "**/.pypirc",
  "**/id_rsa",
  "**/id_ed25519",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.kdbx",
  "**/auth.json",
];

interface CompiledPattern {
  re: RegExp;
  negate: boolean;
}

/** Convert a glob pattern to a RegExp. Supports **, *, negation prefix. */
function globToRegExp(pattern: string): CompiledPattern {
  let negate = false;
  let p = pattern;
  if (p.startsWith("!")) { negate = true; p = p.slice(1); }

  let re = "";
  let i = 0;
  while (i < p.length) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        re += ".*";
        i += 2;
        if (p[i] === "/") i++;
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (c === "?") {
      re += "[^/]";
      i += 1;
    } else if (c === ".") {
      re += "\\.";
      i += 1;
    } else if ("+()[]{}^$|".includes(c)) {
      re += "\\" + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  return { re: new RegExp(re + "$"), negate };
}

/** Resolve a local path and its symlinked ancestors, including missing write targets. */
export function resolveFilesystemPathCandidates(
  filePath: string,
  baseCwd = process.cwd(),
): string[] {
  if (!filePath) return [];
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(filePath)) return [filePath];

  const home = process.env.HOME || os.homedir();
  const expanded = filePath === "~"
    ? home
    : filePath.startsWith("~/")
      ? path.join(home, filePath.slice(2))
      : filePath;
  const absolutePath = path.resolve(baseCwd, expanded);
  const missingSegments: string[] = [];
  let ancestor = absolutePath;
  let resolvedPath = absolutePath;

  while (true) {
    try {
      resolvedPath = path.resolve(fs.realpathSync(ancestor), ...missingSegments);
      break;
    } catch {
      const parent = path.dirname(ancestor);
      if (parent === ancestor) break;
      missingSegments.unshift(path.basename(ancestor));
      ancestor = parent;
    }
  }

  return resolvedPath === absolutePath ? [absolutePath] : [absolutePath, resolvedPath];
}

/**
 * Glob matcher for protected paths.
 * Stateless after construction; safe to call concurrently.
 */
export class ProtectedPathMatcher {
  private readonly patterns: string[];
  private readonly compiled: CompiledPattern[];

  constructor(patterns: string[] = DEFAULT_PROTECTED_PATHS) {
    this.patterns = patterns;
    this.compiled = patterns.map(globToRegExp);
  }

  /** Check if a path matches any protected pattern, including symlinked parents. */
  isProtected(filePath: string, baseCwd = process.cwd()): boolean {
    if (!filePath || this.patterns.length === 0) return false;

    for (const candidate of resolveFilesystemPathCandidates(filePath, baseCwd)) {
      const normalized = candidate.replace(/\\/g, "/");
      const basename = path.basename(candidate);

      let matched = false;
      for (const { re, negate } of this.compiled) {
        if (re.test(normalized) || re.test(basename)) {
          matched = !negate;
        }
      }
      if (matched) return true;
    }
    return false;
  }
}
