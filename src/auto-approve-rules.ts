/**
 * Terminal command auto-approval rules.
 *
 * Ported from VS Code's default `chat.tools.terminal.autoApprove` table:
 *   src/vs/platform/terminal/common/autoApprove/defaultAutoApproveRules.ts
 *   src/vs/platform/terminal/common/autoApprove/gitAutoApproveRules.ts
 *   src/vs/platform/terminal/common/autoApprove/sortAutoApproveRules.ts
 *
 * Copyright (c) Microsoft Corporation. Licensed under the MIT License.
 * See THIRD_PARTY_NOTICES.md.
 *
 * Rule keys follow VS Code's syntax:
 * - `/pattern/flags` is a JavaScript regular expression.
 * - A key containing a path separator is a path prefix rule.
 * - Anything else is an escaped prefix with a word boundary.
 * A `false` value means "never auto-approve"; it does not by itself mean the
 * command is destructive. In smart-approve a deny becomes a reviewable
 * behavior, and the critical behaviors still take precedence.
 */

export type AutoApproveRuleValue =
  | boolean
  | { approve: boolean; matchCommandLine?: boolean };

const GIT_AUTO_APPROVE_RULES: Readonly<Record<string, AutoApproveRuleValue>> = {
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+status\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+log\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+log\\b.*\\s--output(=|\\s|$)/": false,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+show\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+show\\b.*\\s--output(=|\\s|$)/": false,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+diff\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+diff\\b.*\\s--[^\\w\\s]*o[^\\w\\s]*u[^\\w\\s]*t[^\\w\\s]*p[^\\w\\s]*u[^\\w\\s]*t[^\\w\\s]*(=|\\s|$)/": false,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+ls-files\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+grep\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+grep\\b.*\\s(?-i:-[aIivwhHEGPFnlLqzco]*[^\\w\\s]*O\\S*)(\\s|$)/": false,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+grep\\b.*\\s(?-i:--[^\\w\\s]*o[^\\w\\s]*p\\S*)(\\s|$)/": false,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+branch\\b/": true,
  "/^git(\\s+(-(?-i:C)\\s+\\S+|--no-pager))*\\s+branch\\b.*\\s-(d|D|m|M|-delete|-force)\\b/": false,
};

const SORT_AUTO_APPROVE_RULES: Readonly<
  Record<string, AutoApproveRuleValue>
> = {
  "/^sort\\b(?!-)/": true,
  "/^sort\\b.*\\s-(o|S)\\b/": false,
  "/^sort\\b.*\\s(?:\\$?['\"]|\\\\)*-(?:\\$?['\"]|\\\\)*-(?:\\$?['\"]|\\\\)*c(?:\\$?['\"]|\\\\)*o/": false,
  "/^sort\\b.*\\s(?:\\$?['\"]|\\\\)*-(?:\\$?['\"]|\\\\)*-(?:\\$?['\"]|\\\\)*o/s": false,
};

/** Default allow/deny rules (POSIX subset of VS Code's defaults). */
export const VSCODE_DEFAULT_AUTO_APPROVE_RULES: Readonly<
  Record<string, AutoApproveRuleValue>
> = {
  // Read-only commands
  cd: true,
  echo: true,
  ls: true,
  dir: true,
  pwd: true,
  cat: true,
  head: true,
  tail: true,
  findstr: true,
  wc: true,
  tr: true,
  cut: true,
  cmp: true,
  which: true,
  basename: true,
  dirname: true,
  realpath: true,
  readlink: true,
  stat: true,
  file: true,
  od: true,
  du: true,
  df: true,
  sleep: true,
  nl: true,
  grep: true,

  // Read-only subcommands
  ...GIT_AUTO_APPROVE_RULES,
  "/^docker\\s+(ps|images|info|version|inspect|logs|top|stats|port|diff|search|events)\\b/": true,
  "/^docker\\s+(container|image|network|volume|context|system)\\s+(ls|ps|inspect|history|show|df|info)\\b/": true,
  "/^docker\\s+compose\\s+(ps|ls|top|logs|images|config|version|port|events)\\b/": true,

  // Package managers: read-only commands
  "/^npm\\s+(ls|list|outdated|view|info|show|explain|why|root|prefix|bin|search|doctor|fund|repo|bugs|docs|home|help(-search)?)\\b/": true,
  "/^npm\\s+config\\s+(list|get)\\b/": true,
  "/^npm\\s+pkg\\s+get\\b/": true,
  "/^npm\\s+audit$/": true,
  "/^npm\\s+cache\\s+verify\\b/": true,
  "/^yarn\\s+(list|outdated|info|why|bin|help|versions)\\b/": true,
  "/^yarn\\s+licenses\\b/": true,
  "/^yarn\\s+audit\\b(?!.*\\bfix\\b)/": true,
  "/^yarn\\s+config\\s+(list|get)\\b/": true,
  "/^yarn\\s+cache\\s+dir\\b/": true,
  "/^pnpm\\s+(ls|list|outdated|why|root|bin|doctor)\\b/": true,
  "/^pnpm\\s+licenses\\b/": true,
  "/^pnpm\\s+audit\\b(?!.*\\bfix\\b)/": true,
  "/^pnpm\\s+config\\s+(list|get)\\b/": true,
  "npm ci": true,
  "/^npm\\s+ci\\s+\\S/": false,
  "/^yarn\\s+install\\s+--frozen-lockfile\\b/": true,
  "/^yarn\\s+install\\s+--frozen-lockfile\\s+\\S/": false,
  "/^pnpm\\s+install\\s+--frozen-lockfile\\b/": true,
  "/^pnpm\\s+install\\s+--frozen-lockfile\\s+\\S/": false,

  // Generally allowed with dangerous flags denied
  column: true,
  "/^column\\b.*\\s-c\\s+[0-9]{4,}/": false,
  date: true,
  "/^date\\b.*\\s(-s|--set)\\b/": false,
  find: true,
  "/^find\\b.*\\s-(delete|exec|execdir|fprint|fprintf|fls|ok|okdir)\\b/": false,
  rg: true,
  "/^rg\\b.*\\s(--pre|--hostname-bin)\\b/": false,
  sed: true,
  "/^sed\\b.*\\s(-[a-zA-Z]*(e|f)[a-zA-Z]*|--expression|--file)\\b/": false,
  "/^sed\\b.*s\\/.*\\/.*\\/[ew]/": false,
  "/^sed\\b(?:\\s+(?:(?:-l|--line-length)\\s+\\S+|--line-length=\\S+|-\\S+))*\\s+(['\"])\\s*(?:(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/)(?:\\s*,\\s*(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/))?)?\\s*!?\\s*[erRwW](?:\\s|\\1)/": false,
  "/^sed\\b(?:\\s+(?:(?:-l|--line-length)\\s+\\S+|--line-length=\\S+|-\\S+))*\\s+(['\"])(?:\\\\.|(?!\\1).)*[;{]\\s*(?:(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/)(?:\\s*,\\s*(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/))?)?\\s*!?\\s*[erRwW](?:\\s|\\1|[;}])/": false,
  "/^sed\\b(?:\\s+(?:(?:-l|--line-length)\\s+\\S+|--line-length=\\S+|-\\S+))*\\s+(?:(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/)(?:\\s*,\\s*(?:\\d+|\\$|\\/(?:\\\\.|[^\\/])*\\/))?)?\\s*!?\\s*[erRwW](?:\\s|$)/": false,
  ...SORT_AUTO_APPROVE_RULES,
  tree: true,
  "/^tree\\b.*\\s-o\\b/": false,
  "/^xxd$/": true,
  "/^xxd\\b(\\s+-\\S+)*\\s+[^-\\s]\\S*$/": true,

  // Explicitly not auto-approved
  rm: false,
  rmdir: false,
  del: false,
  erase: false,
  dd: false,
  kill: false,
  ps: false,
  top: false,
  taskkill: false,
  "taskkill.exe": false,
  curl: false,
  wget: false,
  chmod: false,
  chown: false,
  jq: false,
  xargs: false,
  eval: false,
};

export interface CompiledAutoApproveRule {
  source: string;
  regex: RegExp;
}

export interface CompiledAutoApproveRules {
  allow: CompiledAutoApproveRule[];
  deny: CompiledAutoApproveRule[];
}

const NEVER_MATCH = /(?!.*)/;

function escapeRegExpCharacters(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** VS Code's `_doConvertAutoApproveEntryToRegex`. */
function ruleToRegex(value: string): RegExp {
  const regexMatch = value.match(/^\/(?<pattern>.+)\/(?<flags>[dgimsuvy]*)$/);
  const pattern = regexMatch?.groups?.pattern;
  if (pattern) {
    const flags = (regexMatch?.groups?.flags ?? "").replaceAll("g", "");
    if (pattern === ".*") return new RegExp(pattern);
    try {
      return new RegExp(pattern, flags || undefined);
    } catch {
      return NEVER_MATCH;
    }
  }

  if (value === "") return NEVER_MATCH;

  if (value.includes("/") || value.includes("\\")) {
    let pattern = value.replace(/[/\\]/g, "%%PATH_SEP%%");
    pattern = escapeRegExpCharacters(pattern);
    pattern = pattern.replace(/%%PATH_SEP%%*/g, "[/\\\\]");
    return new RegExp(`^(?:\\.[/\\\\])?${pattern}`);
  }

  return new RegExp(`^${escapeRegExpCharacters(value)}\\b`);
}

export function compileAutoApproveRules(
  rules: Readonly<Record<string, AutoApproveRuleValue>>,
): CompiledAutoApproveRules {
  const allow: CompiledAutoApproveRule[] = [];
  const deny: CompiledAutoApproveRule[] = [];
  for (const [source, value] of Object.entries(rules)) {
    const matched =
      typeof value === "boolean"
        ? { approve: value, matchCommandLine: false }
        : value;
    if (matched.matchCommandLine === true) continue;
    const compiled = { source, regex: ruleToRegex(source) };
    (matched.approve ? allow : deny).push(compiled);
  }
  return { allow, deny };
}

export type AutoApproveResult = "approved" | "denied" | "manual";

/** Deny rules win; a command needs an explicit allow rule to be approved. */
export function evaluateAutoApprove(
  command: string,
  rules: CompiledAutoApproveRules,
): { result: AutoApproveResult; rule?: string } {
  const trimmed = command.trim();
  if (!trimmed) return { result: "manual" };
  for (const rule of rules.deny) {
    if (rule.regex.test(trimmed)) {
      return { result: "denied", rule: rule.source };
    }
  }
  for (const rule of rules.allow) {
    if (rule.regex.test(trimmed)) {
      return { result: "approved", rule: rule.source };
    }
  }
  return { result: "manual" };
}
