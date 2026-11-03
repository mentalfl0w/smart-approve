/**
 * Smart Approve — behavior detection.
 *
 * Behavior-based detection parses executable positions, arguments, and
 * filesystem targets so text in messages or output is not treated as code.
 * Only shell-grammar constructs such as fork bombs and code piped to an
 * interpreter use syntax patterns; substitutions are analyzed separately.
 */

import type { DangerAnalysis } from "./types";
import { makeLabel } from "./i18n";
import { resolveFilesystemPathCandidates } from "./paths";
import * as os from "node:os";
import * as path from "node:path";

// ── Behavior catalog ─────────────────────────────────────────────────

const BEHAVIORS: Record<string, { en: string; zh: string }> = {
  "recursive-force-delete": makeLabel("Recursive force delete (rm -rf)", "递归强制删除 rm -rf"),
  "delete-root": makeLabel("Delete root path /", "删除根路径 /"),
  "delete-sys-dir": makeLabel("Delete system directory", "删除系统目录"),
  "fork-bomb": makeLabel("Fork bomb", "Fork bomb"),
  "remote-fetch-exec": makeLabel("Remote fetch-and-execute (curl|sh)", "远程拉取即执行 (curl|sh)"),
  "write-sensitive-file": makeLabel("Write to system-sensitive file", "写系统敏感文件"),
  "write-block-device": makeLabel("Write to raw block device", "写裸块设备"),
  "chmod-sys-dir": makeLabel("Change system directory permissions", "改系统目录权限"),
  "shutdown-reboot": makeLabel("Shutdown / reboot", "关机/重启"),
  "disk-format": makeLabel("Disk format / raw write", "格式化/裸写块设备"),
  "mount-block-device": makeLabel("Mount / unmount block device", "挂载/卸载块设备"),
  "force-kill": makeLabel("Force kill process (SIGKILL)", "强杀进程 SIGKILL"),
  "pkg-global-uninstall": makeLabel("Global package uninstall", "全局卸载包"),
  "git-force-push": makeLabel("git force / mirror push", "git 强制/镜像推送"),
  "git-push-delete": makeLabel("git push --delete (remote ref)", "git push --delete 删远程引用"),
  "git-push-colon-ref": makeLabel("git push :ref (delete remote branch)", "git push :ref 删远程分支"),
  "git-hard-reset": makeLabel("git reset --hard (discard changes)", "git reset --hard 丢弃改动"),
  "git-clean": makeLabel("git clean -f (delete untracked)", "git clean -f 删未跟踪文件"),
  "git-branch-delete": makeLabel("git branch -D (force delete)", "git branch -D 强删分支"),
  "git-tag-delete": makeLabel("git tag -d (delete tag)", "git tag -d 删标签"),
  "git-stash-clear": makeLabel("git stash clear", "git stash clear 清空 stash"),
  "git-stash-drop": makeLabel("git stash drop", "git stash drop 丢 stash"),
  "git-reflog-expire": makeLabel("git reflog expire", "git reflog expire 清引用日志"),
  "git-gc-prune": makeLabel("git gc --prune (purge objects)", "git gc --prune 清理对象"),
  "git-filter-branch": makeLabel("git filter-branch (rewrite history)", "git filter-branch 重写历史"),
  "git-filter-repo": makeLabel("git filter-repo (rewrite history)", "git filter-repo 重写历史"),
  "git-commit-amend": makeLabel("git commit --amend", "git commit --amend 修订提交"),
  "git-rebase": makeLabel("git rebase (rewrite history)", "git rebase 重写历史"),
  "git-remote-rm": makeLabel("git remote rm", "git remote rm 移除远程"),
  "git-submodule-deinit": makeLabel("git submodule deinit", "git submodule deinit"),
  "git-worktree-remove": makeLabel("git worktree remove", "git worktree remove"),
  "git-update-ref-delete": makeLabel("git update-ref -d (delete ref)", "git update-ref -d 删引用"),
  "git-checkout-discard": makeLabel("git checkout -- . (discard all)", "git checkout -- . 丢所有改动"),
  "git-restore-discard": makeLabel("git restore . (discard worktree)", "git restore . 丢工作区改动"),
  "git-config-global": makeLabel("git config --global", "git config --global 改全局配置"),
  "git-notes-remove": makeLabel("git notes remove", "git notes remove 删 notes"),
  "docker-destroy": makeLabel("docker rm/rmi/volume/network rm", "docker 删除容器/镜像/卷"),
  "kubectl-delete": makeLabel("kubectl delete", "kubectl delete"),
  "mv-sys-dir": makeLabel("Move system directory", "移动系统目录"),
  "cp-root": makeLabel("Recursive copy to root", "递归拷贝到根"),
  "git-force-push-protected": makeLabel("git force push to protected branch", "git 强制推送到保护分支"),
  "delete-home": makeLabel("Delete home directory (~)", "删除家目录 ~"),
  "high-risk-executable": makeLabel("High-risk process launch", "启动高风险程序"),
  "interpreter-inline-execution": makeLabel("Interpreter executes inline code", "解释器执行内联代码"),
  "permission-change": makeLabel("Changes file permissions or ownership", "修改文件权限或所有者"),
  "dd-write": makeLabel("Writes data to a file with dd", "使用 dd 写入文件"),
  "sensitive-file-reference": makeLabel("Access to protected system account files", "访问受保护的系统账号文件"),
  "sensitive-working-directory": makeLabel("Runs outside the session in a sensitive directory", "在会话目录外的敏感目录运行"),
};

// Regexes over arbitrary arguments caused false positives in commit messages
// and other data. Retain only this shell-grammar signature; command families
// are matched from parsed executable names and arguments below.
const FORK_BOMB_PATTERN = /(?:^|[;&|])\s*:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
const HIGH_RISK_EXECUTABLES: Record<string, true> = {
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

const INTERPRETERS: Record<string, true> = {
  sh: true, bash: true, zsh: true, dash: true, csh: true, tcsh: true, ksh: true, fish: true,
  node: true, nodejs: true, bun: true, deno: true, ruby: true, perl: true, php: true,
  lua: true, tclsh: true, expect: true,
};

function unquoteToken(token: string): string {
  if (
    token.length >= 2 &&
    ((token[0] === "'" && token[token.length - 1] === "'") ||
      (token[0] === "\"" && token[token.length - 1] === "\""))
  ) {
    return token.slice(1, -1);
  }
  return token;
}

function isAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(unquoteToken(token));
}
function splitShellCommands(command: string): string[] {
  const result: string[] = [];
  let start = 0;
  let quote: string | undefined;
  let escaped = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
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
      const segment = command.slice(start, i).trim();
      if (segment) result.push(segment);
      start = i + 1;
      if ((ch === "|" || ch === "&") && command[i + 1] === ch) i++;
    }
  }

  const tail = command.slice(start).trim();
  if (tail) result.push(tail);
  return result;
}

/** Remove shell comments without treating `#` inside quotes as a comment. */
function stripShellComments(command: string): string {
  let result = "";
  let quote: string | undefined;
  let escaped = false;
  let comment = false;

  for (let index = 0; index < command.length; index++) {
    const ch = command[index];
    if (comment) {
      if (ch === "\n") {
        result += ch;
        comment = false;
      } else {
        result += " ";
      }
      continue;
    }
    if (quote !== undefined) {
      result += ch;
      if (escaped) escaped = false;
      else if (ch === "\\" && quote !== "'") escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === "\"" || ch === "`") {
      quote = ch;
      result += ch;
      continue;
    }
    if (
      ch === "#" &&
      (index === 0 || /[\s;&|]/.test(command[index - 1]))
    ) {
      comment = true;
      result += " ";
      continue;
    }
    result += ch;
  }
  return result;
}

/** Remove quoted data before applying regex rules that describe shell syntax.
 *  Keep double-quoted command substitutions and backticks: they execute code. */
function stripQuotedShellData(command: string): string {
  const source = stripShellComments(command);
  let result = "";
  for (let index = 0; index < source.length; index++) {
    const quote = source[index];
    if (quote !== "'" && quote !== "\"") {
      result += quote;
      continue;
    }
    let cursor = index + 1;
    let escaped = false;
    while (cursor < source.length) {
      const ch = source[cursor];
      if (escaped) escaped = false;
      else if (quote === "\"" && ch === "\\") escaped = true;
      else if (ch === quote) break;
      cursor++;
    }
    const contents = source.slice(index + 1, cursor);
    const executesSubstitution = quote === "\"" && /(?:\$\(|`)/.test(contents);
    const literal = source.slice(index, Math.min(cursor + 1, source.length));
    result += executesSubstitution
      ? literal
      : literal.replace(/[^\n]/g, " ");
    index = cursor;
  }
  return result;
}
interface ShellSubstitution {
  start: number;
  end: number;
  body: string;
}

function findClosingParenthesis(source: string, open: number): number {
  let depth = 1;
  let quote: string | undefined;
  let escaped = false;

  for (let index = open + 1; index < source.length; index++) {
    const ch = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\" && quote !== "'") {
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
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return index;
  }
  return -1;
}

function findClosingBacktick(source: string, start: number): number {
  for (let index = start + 1; index < source.length; index++) {
    if (source[index] === "\\") {
      index++;
      continue;
    }
    if (source[index] === "`") return index;
  }
  return -1;
}

/** Find executable substitutions, including those inside double quotes. */
function findShellSubstitutions(source: string): ShellSubstitution[] {
  const substitutions: ShellSubstitution[] = [];
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < source.length; index++) {
    const ch = source[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote === "'") {
      if (ch === "'") quote = undefined;
      continue;
    }
    if (quote === "\"") {
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === "\"") {
        quote = undefined;
        continue;
      }
    } else if (ch === "\\") {
      escaped = true;
      continue;
    } else if (ch === "'") {
      quote = "'";
      continue;
    } else if (ch === "\"") {
      quote = "\"";
      continue;
    }

    if (ch === "`") {
      const closing = findClosingBacktick(source, index);
      if (closing >= 0) {
        substitutions.push({
          start: index,
          end: closing + 1,
          body: source.slice(index + 1, closing),
        });
        index = closing;
      }
      continue;
    }

    const processSubstitution =
      quote !== "\"" && (ch === "<" || ch === ">") && source[index + 1] === "(";
    const commandSubstitution = ch === "$" && source[index + 1] === "(";
    if (!processSubstitution && !commandSubstitution) continue;

    const open = index + 1;
    const closing = findClosingParenthesis(source, open);
    if (closing < 0) continue;
    substitutions.push({
      start: index,
      end: closing + 1,
      body: source.slice(open + 1, closing),
    });
    index = closing;
  }
  return substitutions;
}

function stripShellSubstitutions(
  command: string,
  substitutions: ShellSubstitution[],
): string {
  if (substitutions.length === 0) return command;
  let result = "";
  let cursor = 0;
  for (const substitution of substitutions) {
    result += command.slice(cursor, substitution.start);
    result += " ".repeat(substitution.end - substitution.start);
    cursor = substitution.end;
  }
  return result + command.slice(cursor);
}



function commandAndArgs(segment: string): { name: string; args: string[] } | undefined {
  const tokens = roughTokenize(segment);
  let index = 0;

  while (index < tokens.length) {
    const token = unquoteToken(tokens[index]);
    const name = path.basename(token).toLowerCase();
    if (isAssignment(tokens[index]) || ["!", "if", "then", "do", "else", "elif"].includes(name)) {
      index++;
      continue;
    }
    if (name === "env") {
      index++;
      while (index < tokens.length) {
        const option = unquoteToken(tokens[index]);
        if (isAssignment(tokens[index])) {
          index++;
          continue;
        }
        if (option === "--") {
          index++;
          break;
        }
        if (!option.startsWith("-")) break;
        index++;
        if (["-u", "--unset", "-C", "--chdir"].includes(option) && index < tokens.length) index++;
      }
      continue;
    }
    if (name === "xargs") {
      index++;
      while (index < tokens.length) {
        const option = unquoteToken(tokens[index]);
        if (option === "--") {
          index++;
          break;
        }
        if (!option.startsWith("-")) break;
        index++;
        if (
          ["-E", "--eof", "-I", "--replace", "-L", "--max-lines", "-n", "--max-args",
            "-P", "--max-procs", "-s", "--max-chars", "-d", "--delimiter", "-a", "--arg-file"].includes(option) &&
          index < tokens.length
        ) {
          index++;
        }
      }
      continue;
    }
    if (["command", "exec", "nohup", "time", "setsid"].includes(name)) {
      index++;
      if (["command", "time"].includes(name) && tokens[index] === "-p") index++;
      if (name === "setsid" && tokens[index] === "-f") index++;
      if (tokens[index] === "--") index++;
      if (name === "exec" && tokens[index] === "-a") index += 2;
      continue;
    }
    if (name === "timeout") {
      index++;
      while (index < tokens.length && tokens[index].startsWith("-")) {
        const option = tokens[index++];
        if (["-k", "--kill-after", "-s", "--signal"].includes(option) && index < tokens.length) index++;
      }
      if (tokens[index] !== undefined) index++;
      continue;
    }
    if (name === "nice") {
      index++;
      if (tokens[index] === "-n") index += 2;
      else if (/^-n\d+$/.test(tokens[index] ?? "")) index++;
      continue;
    }
    return {
      name,
      args: tokens.slice(index + 1).map(unquoteToken),
    };
  }

  return undefined;
}

function findExecCommands(args: string[]): string[][] {
  const commands: string[][] = [];
  for (let index = 0; index < args.length; index++) {
    if (!["-exec", "-execdir", "-ok", "-okdir"].includes(args[index])) continue;
    const start = index + 1;
    let end = start;
    while (
      end < args.length &&
      args[end] !== ";" &&
      args[end] !== "\\;" &&
      !(args[end] === "+" && (end === args.length - 1 || args[end + 1].startsWith("-")))
    ) {
      end++;
    }
    if (end > start) commands.push(args.slice(start, end));
    index = end;
  }
  return commands;
}

function quoteShellArgument(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function hasRecursiveForceFlags(args: string[]): boolean {
  let recursive = false;
  let force = false;
  for (const arg of args) {
    if (arg === "--") break;
    if (arg === "--recursive") recursive = true;
    else if (arg === "--force") force = true;
    else if (/^-[^-]+$/.test(arg)) {
      const flags = arg.slice(1).toLowerCase();
      recursive ||= flags.includes("r");
      force ||= flags.includes("f");
    }
  }
  return recursive && force;
}

function isSensitiveAccountFilePath(value: string): boolean {
  return /(?:^|\/)etc\/(?:passwd|shadow|sudoers)(?:$|[./])/i.test(value);
}

function isGitMessageArgument(args: string[], index: number): boolean {
  const subcommand = skipGitGlobalOptions(args)?.subcommand;
  if (!["commit", "tag", "notes"].includes(subcommand ?? "")) return false;
  const value = args[index];
  return (
    args[index - 1] === "-m" ||
    args[index - 1] === "--message" ||
    value.startsWith("--message=") ||
    (value.startsWith("-m") && !value.startsWith("--"))
  );
}

function findGrepTextArguments(args: string[]): Set<number> {
  const textArguments = new Set<number>();
  let explicitPattern = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") {
      if (!explicitPattern && args[index + 1] !== undefined) textArguments.add(index + 1);
      break;
    }
    if (arg === "-e" || arg === "--regexp") {
      explicitPattern = true;
      if (args[index + 1] !== undefined) textArguments.add(++index);
      continue;
    }
    if (
      arg.startsWith("--regexp=") ||
      arg.startsWith("--glob=") ||
      arg.startsWith("--iglob=") ||
      arg.startsWith("--include=") ||
      arg.startsWith("--exclude=") ||
      arg.startsWith("--exclude-dir=") ||
      arg.startsWith("--type=") ||
      arg.startsWith("--max-count=") ||
      (arg.startsWith("-e") && !arg.startsWith("--") && arg.length > 2) ||
      /^-g.+/.test(arg) ||
      /^-t.+/.test(arg)
    ) {
      if (
        arg.startsWith("--regexp=") ||
        (arg.startsWith("-e") && !arg.startsWith("--") && arg.length > 2)
      ) {
        explicitPattern = true;
      }
      textArguments.add(index);
      continue;
    }
    if (arg === "--exclude-from" && args[index + 1] !== undefined) {
      index++;
      continue;
    }
    if (arg.startsWith("-")) {
      if (
        ["-A", "-B", "-C", "-d", "-g", "-m", "-t", "--after-context", "--before-context", "--context",
          "--directories", "--exclude", "--exclude-dir", "--glob", "--iglob",
          "--include", "--label", "--max-count", "--sort", "--sortr", "--threads", "--type",
          "--type-add"].includes(arg) &&
        args[index + 1] !== undefined
      ) {
        textArguments.add(index + 1);
        index++;
      } else if (["-f", "--file"].includes(arg) && args[index + 1] !== undefined) {
        index++;
      }
      continue;
    }
    if (!explicitPattern) textArguments.add(index);
    break;
  }
  return textArguments;
}

function findSedScriptArguments(args: string[]): Set<number> {
  const scripts = new Set<number>();
  let foundScript = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "-e" || arg === "--expression") {
      foundScript = true;
      if (args[index + 1] !== undefined) scripts.add(++index);
    } else if (arg.startsWith("--expression=") || (arg.startsWith("-e") && arg.length > 2)) {
      foundScript = true;
      scripts.add(index);
    } else if (arg === "-f" || arg === "--file") {
      if (args[index + 1] !== undefined) index++;
    } else if (arg.startsWith("-")) {
      continue;
    } else if (!foundScript) {
      foundScript = true;
      scripts.add(index);
    }
  }
  return scripts;
}

function findAwkTextArguments(args: string[]): Set<number> {
  const textArguments = new Set<number>();
  let foundProgram = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (["-v", "--assign", "-F"].includes(arg)) {
      if (args[index + 1] !== undefined) textArguments.add(++index);
    } else if (/^-(?:v|F).+/.test(arg)) {
      textArguments.add(index);
    } else if (arg === "-f" || arg === "--file") {
      if (args[index + 1] !== undefined) index++;
    } else if (arg.startsWith("-")) {
      continue;
    } else if (!foundProgram) {
      foundProgram = true;
      textArguments.add(index);
    }
  }
  return textArguments;
}

function isSearchTextArgument(name: string, args: string[], index: number): boolean {
  if (["grep", "egrep", "fgrep", "rg", "ripgrep"].includes(name)) {
    return findGrepTextArguments(args).has(index);
  }
  if (name === "sed") return findSedScriptArguments(args).has(index);
  if (name === "awk" || name === "gawk") return findAwkTextArguments(args).has(index);
  if (name !== "git") return false;

  const command = skipGitGlobalOptions(args);
  if (!command) return false;
  const argumentIndex = index - (args.length - command.rest.length);
  if (argumentIndex < 0 || argumentIndex >= command.rest.length) return false;
  if (command.subcommand === "grep") {
    return findGrepTextArguments(command.rest).has(argumentIndex);
  }
  if (command.subcommand !== "log" && command.subcommand !== "show") return false;
  const arg = command.rest[argumentIndex];
  return (
    arg.startsWith("--grep=") ||
    arg.startsWith("--author=") ||
    arg.startsWith("--committer=") ||
    /^-[SG].+/.test(arg) ||
    ["--grep", "--author", "--committer", "-S", "-G"].includes(command.rest[argumentIndex - 1] ?? "")
  );
}

function hasSensitiveAccountFileReference(name: string, args: string[]): boolean {
  if (name === "echo" || name === "printf") return false;
  return args.some((value, index) =>
    isSensitiveAccountFilePath(value) &&
    !(name === "git" && isGitMessageArgument(args, index)) &&
    !isSearchTextArgument(name, args, index),
  );
}



function redirectionTargets(segment: string): string[] {
  const targets: string[] = [];
  let quote: string | undefined;
  let escaped = false;

  for (let index = 0; index < segment.length; index++) {
    const ch = segment[index];
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (ch === "\\" && quote === "\"") escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "\\" ) {
      index++;
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (ch !== ">") continue;

    let cursor = index + 1;
    if (segment[cursor] === ">") cursor++;
    while (/\s/.test(segment[cursor] ?? "")) cursor++;
    if (segment[cursor] === "&" || segment[cursor] === "|") continue;

    let target = "";
    const targetQuote = segment[cursor];
    if (targetQuote === "'" || targetQuote === "\"") {
      cursor++;
      while (cursor < segment.length && segment[cursor] !== targetQuote) {
        if (segment[cursor] === "\\" && targetQuote === "\"" && cursor + 1 < segment.length) cursor++;
        target += segment[cursor++];
      }
      if (segment[cursor] === targetQuote) cursor++;
    } else {
      while (cursor < segment.length && !/[\s;&|()<>\n]/.test(segment[cursor])) {
        target += segment[cursor++];
      }
    }
    if (target) targets.push(target);
    index = cursor - 1;
  }
  return targets;
}

function hasInterpreterExecutionFlag(args: string[]): boolean {
  return args.some((arg) =>
    arg === "-c" ||
    arg === "-e" ||
    arg === "-i" ||
    arg === "--eval" ||
    arg === "--command" ||
    /^-[^-]*[cei]/.test(arg) ||
    /^(?:--eval|--command)=/.test(arg),
  );
}

const SENSITIVE_DIRS = [
  "/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/Library", "/System", "/private",
];
const TEMPORARY_DIRS = [
  "/tmp",
  "/private/tmp",
  "/var/tmp",
  "/private/var/tmp",
  "/var/folders",
  "/private/var/folders",
];

function isWithinDirectory(candidate: string, directory: string): boolean {
  return candidate === directory ||
    candidate.startsWith(directory === path.sep ? path.sep : `${directory}${path.sep}`);
}


/**
 * True when `cwd` is inside a sensitive system location and outside the
 * session root.  Lexical and canonical candidates are compared for both the
 * working directory and every sensitive directory, so a symlinked
 * `~/.ssh` / `~/.gnupg` is still recognized after canonicalization.
 * Relative `cwd` values resolve against `baseCwd` (defaulting to
 * `sessionCwd`); URLs are not local.  Shared with the Eval gate for its cwd
 * checks.
 */
export function isSensitiveWorkingDirectory(
  cwd: string,
  sessionCwd: string,
  baseCwd = sessionCwd,
): boolean {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(cwd)) return false;
  const candidates = resolveFilesystemPathCandidates(cwd, baseCwd);
  if (candidates.length === 0) return false;

  const home = process.env.HOME || os.homedir();
  const sensitiveSystemCandidates = SENSITIVE_DIRS.flatMap((directory) =>
    resolveFilesystemPathCandidates(directory, directory),
  );
  const sensitiveHomeCandidates = [path.join(home, ".ssh"), path.join(home, ".gnupg")]
    .flatMap((directory) => resolveFilesystemPathCandidates(directory, directory));
  const temporaryCandidates = TEMPORARY_DIRS.flatMap((directory) =>
    resolveFilesystemPathCandidates(directory, directory),
  );

  const sensitive = candidates.some((candidate) =>
    sensitiveHomeCandidates.some((directory) => isWithinDirectory(candidate, directory)) ||
    (
      sensitiveSystemCandidates.some((directory) => isWithinDirectory(candidate, directory)) &&
      !temporaryCandidates.some((directory) => isWithinDirectory(candidate, directory))
    ),
  );
  if (!sensitive) return false;

  const sessionCandidates = resolveFilesystemPathCandidates(sessionCwd, sessionCwd);
  return !candidates.some((candidate) =>
    sessionCandidates.some(
      (directory) =>
        candidate === directory ||
        candidate.startsWith(directory === path.sep ? path.sep : `${directory}${path.sep}`),
    ),
  );
}


// ── Git argument parser ──────────────────────────────────────────────
//
// Parses git subcommand + flags to detect behaviors that regex misses
// (e.g. `git push origin +branch` = force-push via +refspec).

function roughTokenize(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
    } else if (/\s/.test(ch)) {
      if (current) { tokens.push(current); current = ""; }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}


function skipGitGlobalOptions(args: string[]): { subcommand: string; rest: string[] } | null {
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) {
    if (["-C", "--git-dir", "--work-tree", "-c"].includes(args[i])) i += 2;
    else i += 1;
    if (i > args.length) return null;
  }
  if (i >= args.length) return null;
  return { subcommand: args[i], rest: args.slice(i + 1) };
}

function isForcePush(args: string[]): boolean {
  for (const arg of args) {
    if (arg === "-f" || arg === "--force" || arg === "--mirror") return true;
    if (arg === "--force-with-lease" || arg.startsWith("--force-with-lease=")) return true;
    if (arg === "--force-if-includes") return true;
    if (arg.startsWith("+") && arg.length > 1 && !arg.startsWith("+-")) return true;
  }
  return false;
}

/** Branches whose force push is deny-tier (regex-confident without AI). */
const PROTECTED_PUSH_BRANCHES: Record<string, true> = {
  main: true, master: true, production: true, prod: true, release: true, trunk: true,
};

/** Extract candidate remote branch names from push args (refspecs). */
function pushTargetBranches(args: string[]): string[] {
  const branches: string[] = [];
  for (const arg of args) {
    if (arg === "--") break;
    if (arg.startsWith("-")) continue;
    let target = arg;
    if (target.includes(":")) target = target.slice(target.lastIndexOf(":") + 1);
    if (target.startsWith("+")) target = target.slice(1);
    // Keep only the leaf: refs/heads/main -> main, origin/main -> main.
    target = target.slice(target.lastIndexOf("/") + 1);
    if (target) branches.push(target);
  }
  return branches;
}

function isBranchDelete(args: string[]): boolean {
  for (const arg of args) {
    if (arg === "--") break;
    if (arg === "-D" || arg === "-d" || arg === "--delete") return true;
    if (arg.startsWith("-") && !arg.startsWith("--")) {
      if (arg.includes("d") || arg.includes("D")) return true;
    }
  }
  return false;
}

function isGitCleanDestructive(args: string[]): boolean {
  for (const arg of args) {
    if (arg === "-n" || arg === "--dry-run") return false;
  }
  for (const arg of args) {
    if (arg === "--") break;
    if (["-f", "--force", "-x", "-X", "-d", "--directories"].includes(arg)) return true;
    if (arg.startsWith("-") && !arg.startsWith("--")) {
      if (/[fxXd]/.test(arg)) return true;
    }
  }
  return false;
}

function isGlobalPackageUninstall(name: string, args: string[]): boolean {
  const globalFlag = args.some((arg) => arg === "-g" || arg === "--global" || arg.startsWith("--global="));
  if (["npm", "pnpm"].includes(name)) {
    return ["uninstall", "remove", "rm"].includes(args[0] ?? "") && globalFlag;
  }
  if (name === "yarn") {
    return (
      (args[0] === "global" && ["remove", "uninstall"].includes(args[1] ?? "")) ||
      (["remove", "uninstall"].includes(args[0] ?? "") && globalFlag)
    );
  }
  return /^pip(?:\d+(?:\.\d+)*)?$/.test(name) && args[0] === "uninstall";
}


/** Detect git behaviors by parsing arguments. Returns behavior ids. */
function analyzeGit(args: string[]): string[] {
  const skipped = skipGitGlobalOptions(args);
  if (!skipped) return [];
  const { subcommand, rest } = skipped;
  switch (subcommand) {
    case "push": {
      const ids: string[] = [];
      if (isForcePush(rest)) {
        ids.push("git-force-push");
        if (pushTargetBranches(rest).some((branch) => PROTECTED_PUSH_BRANCHES[branch] === true)) {
          ids.push("git-force-push-protected");
        }
      }
      if (rest.includes("--delete") || rest.some((arg) => arg.startsWith("--delete="))) {
        ids.push("git-push-delete");
      }
      if (rest.some((arg) => arg.startsWith(":") && arg.length > 1)) {
        ids.push("git-push-colon-ref");
      }
      return ids;
    }
    case "branch":
      return isBranchDelete(rest) ? ["git-branch-delete"] : [];
    case "worktree":
      return (rest[0] === "remove" || rest[0] === "rm") ? ["git-worktree-remove"] : [];
    case "reset":
      return rest.includes("--hard") ? ["git-hard-reset"] : [];
    case "clean":
      return isGitCleanDestructive(rest) ? ["git-clean"] : [];
    case "tag":
      return rest.some((arg) => arg === "-d" || arg === "--delete" || /^-[^-]*d/.test(arg))
        ? ["git-tag-delete"]
        : [];
    case "stash":
      return rest[0] === "clear"
        ? ["git-stash-clear"]
        : rest[0] === "drop"
          ? ["git-stash-drop"]
          : [];
    case "reflog":
      return rest[0] === "expire" ? ["git-reflog-expire"] : [];
    case "gc":
      return rest.some((arg) => arg === "--prune" || arg.startsWith("--prune="))
        ? ["git-gc-prune"]
        : [];
    case "filter-branch":
      return ["git-filter-branch"];
    case "filter-repo":
      return ["git-filter-repo"];
    case "commit":
      return rest.includes("--amend") ? ["git-commit-amend"] : [];
    case "remote":
      return ["rm", "remove"].includes(rest[0] ?? "") ? ["git-remote-rm"] : [];
    case "submodule":
      return rest[0] === "deinit" ? ["git-submodule-deinit"] : [];
    case "update-ref":
      return rest.some((arg) => arg === "-d" || arg === "--delete" || /^-[^-]*d/.test(arg))
        ? ["git-update-ref-delete"]
        : [];
    case "checkout": {
      const separator = rest.indexOf("--");
      return separator >= 0 && rest.length > separator + 1 ? ["git-checkout-discard"] : [];
    }
    case "restore":
      return rest.some((arg) => !arg.startsWith("-") && arg !== "--")
        ? ["git-restore-discard"]
        : [];
    case "config":
      return rest.some((arg) => arg === "--global" || arg.startsWith("--global="))
        ? ["git-config-global"]
        : [];
    case "rebase":
      return ["--abort", "--continue", "--skip"].includes(rest[0] ?? "") ? [] : ["git-rebase"];
    case "notes": {
      let index = 0;
      while (index < rest.length && rest[index].startsWith("-")) {
        if (rest[index] === "--ref") index += 2;
        else index++;
      }
      return rest[index] === "remove" ? ["git-notes-remove"] : [];
    }
    default:
      return [];
  }
}

// ── Composite analysis ───────────────────────────────────────────────

/** Behaviors that are always hard-blocked (no LLM review, no allow).
 *  These mirror the former HubLaunchGuard's no-override rejections:
 *  legacy high-risk launches, destructive filesystem commands, and
 *  sensitive working directories. */
const HARD_BLOCK_BEHAVIORS: Record<string, true> = {
  "recursive-force-delete": true,
  "delete-root": true,
  "fork-bomb": true,
  "remote-fetch-exec": true,
  "write-sensitive-file": true,
  "sensitive-file-reference": true,
  "write-block-device": true,
  "disk-format": true,
  "shutdown-reboot": true,
  "high-risk-executable": true,
  "interpreter-inline-execution": true,
  "permission-change": true,
  "dd-write": true,
  "sensitive-working-directory": true,
};

/** Deny-tier behaviors: regex-confident enough to block without an LLM
 *  verdict when auto mode falls back to regex-only decisions.  Hard-blocked
 *  commands never report deny tier — the harder tier wins. */
const DENY_TIER_BEHAVIORS: Record<string, true> = {
  "git-force-push-protected": true,
};

/** Normalize shell input without treating `#` inside quotes as a comment. */
export function normalize(cmd: string): string {
  return stripShellComments(String(cmd ?? ""))
    .replace(/[ \t\r]+/g, " ")
    .replace(/\n{2,}/g, "\n")
    .trim();
}

/**
 * Match parsed executable positions and arguments. Narrow syntax patterns
 * handle shell constructs; command substitutions are analyzed separately,
 * while commit messages, output data, and comments remain data.
 */
export function analyzeCommand(cmd: string): DangerAnalysis {
  const behaviorSet = new Set<string>();
  const pending = [String(cmd ?? "")];

  while (pending.length > 0) {
    const command = normalize(pending.pop() ?? "");
    const substitutions = findShellSubstitutions(command);
    for (const substitution of substitutions) pending.push(substitution.body);

    const executableCommand = stripShellSubstitutions(command, substitutions);
    const syntax = stripQuotedShellData(executableCommand);
    const segments = splitShellCommands(executableCommand);

    for (const segment of segments) {
      const invocation = commandAndArgs(segment);
      if (!invocation) continue;
      const { name, args } = invocation;

      if (name === "git") {
        for (const behavior of analyzeGit(args)) behaviorSet.add(behavior);
      }
      if (name === "find") {
        for (const commandArgs of findExecCommands(args)) {
          pending.push(commandArgs.map(quoteShellArgument).join(" "));
        }
      }
      if (isGlobalPackageUninstall(name, args)) behaviorSet.add("pkg-global-uninstall");
      if (HIGH_RISK_EXECUTABLES[name] === true) behaviorSet.add("high-risk-executable");
      if (
        INTERPRETERS[name] === true ||
        /^(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)$/.test(name) ||
        /^node\d+(?:\.\d+)*$/.test(name)
      ) {
        if (hasInterpreterExecutionFlag(args)) behaviorSet.add("interpreter-inline-execution");
      }
      if (name === "chmod" || name === "chown") behaviorSet.add("permission-change");

      const positional = args.filter((arg) => arg !== "--" && !arg.startsWith("-"));
      const destination = positional[positional.length - 1];
      const recursiveForce = name === "rm" && hasRecursiveForceFlags(args);
      if (recursiveForce) behaviorSet.add("recursive-force-delete");
      if (name === "rm" && positional.includes("/")) behaviorSet.add("delete-root");
      if (
        name === "rm" &&
        positional.some((target) =>
          /^\/(?:usr|etc|var|bin|sbin|boot|dev|proc|sys|root|home|Library)(?:\/|$)/i.test(target),
        )
      ) {
        behaviorSet.add("delete-sys-dir");
      }
      if (
        recursiveForce &&
        positional.some((target) =>
          target === "~" ||
          target.startsWith("~/") ||
          target === "$HOME" ||
          target.startsWith("$HOME/") ||
          /^\/Users\/[^/]+(?:\/|$)/.test(target),
        )
      ) {
        behaviorSet.add("delete-home");
      }
      if (name === "rmdir" && positional.includes("/")) {
        behaviorSet.add("recursive-force-delete");
      }

      if (
        ["shutdown", "poweroff", "halt", "reboot"].includes(name) ||
        (name === "init" && args.some((arg) => arg === "0" || arg === "6"))
      ) {
        behaviorSet.add("shutdown-reboot");
      }
      if (
        name === "systemctl" &&
        ["shutdown", "poweroff", "halt", "reboot"].includes(args.find((arg) => !arg.startsWith("-")) ?? "")
      ) {
        behaviorSet.add("shutdown-reboot");
      }

      if (hasSensitiveAccountFileReference(name, args)) {
        behaviorSet.add("sensitive-file-reference");
      }
      const writesSensitiveFile =
        (name === "tee" && positional.some((arg) => /^\/etc\/(?:passwd|shadow|sudoers|hosts)$/i.test(arg))) ||
        (["cp", "mv", "install", "sed", "perl"].includes(name) &&
          destination !== undefined &&
          /^\/etc\/(?:passwd|shadow|sudoers|hosts)$/i.test(destination));
      if (writesSensitiveFile) behaviorSet.add("write-sensitive-file");
      if (name === "dd" && args.some((arg) => /^of=/.test(arg))) behaviorSet.add("dd-write");
      if (name === "mkfs" || name.startsWith("mkfs.")) behaviorSet.add("disk-format");
      if (
        (name === "mount" || name === "umount") &&
        args.some((arg) => /^\/dev\/(?:sd|nvme|disk)/i.test(arg))
      ) {
        behaviorSet.add("mount-block-device");
      }
      if (
        (name === "kill" && args.some((arg) => /^-(?:9|\d+)$/.test(arg))) ||
        (["pkill", "killall"].includes(name) && args.some((arg) => /-[a-zA-Z]*9/.test(arg)))
      ) {
        behaviorSet.add("force-kill");
      }
      if (name === "mv" && positional.some((target) =>
        /^\/(?:usr|etc|var|bin)(?:\/|$)/i.test(target),
      )) {
        behaviorSet.add("mv-sys-dir");
      }
      if (name === "cp" && args.some((arg) => /-[a-zA-Z]*r/i.test(arg)) && positional.includes("/")) {
        behaviorSet.add("cp-root");
      }
      if (
        name === "docker" &&
        (["rm", "rmi"].includes(args[0] ?? "") ||
          (["volume", "network"].includes(args[0] ?? "") && args[1] === "rm"))
      ) {
        behaviorSet.add("docker-destroy");
      }
      if (name === "kubectl" && args[0] === "delete") {
        behaviorSet.add("kubectl-delete");
      }

      for (const target of redirectionTargets(segment)) {
        const normalized = target.replace(/\\/g, "/");
        const sensitiveSystemWrite =
          /^(?:\/private)?\/etc\/(?:passwd|shadow|sudoers|hosts)(?:$|[./])/i.test(normalized) ||
          /^\/(?:proc|sys)(?:\/|$)/i.test(normalized);
        const blockDeviceWrite =
          /^\/dev\/(?:sd[a-z]\d*|nvme\d+(?:n\d+)?(?:p\d+)?|disk\d+(?:s\d+)?|hd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|mmcblk\d+(?:p\d+)?|mapper\/[^/]+|md\d+|sg\d+|st\d+|nst\d+)$/i.test(normalized);
        if (sensitiveSystemWrite || blockDeviceWrite) behaviorSet.add("write-sensitive-file");
        if (blockDeviceWrite) behaviorSet.add("write-block-device");
      }
    }

    if (FORK_BOMB_PATTERN.test(syntax)) behaviorSet.add("fork-bomb");
    if (
      /(?:^|[;&|])\s*(?:echo|printf)\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|python3?|perl|ruby|node)\b/i.test(syntax) ||
      /(?:^|[;&|])\s*(?:(?:env|command|nohup)\s+)*fetch\b[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|python3?|perl|ruby|node)\b/i.test(syntax)
    ) {
      behaviorSet.add("remote-fetch-exec");
    }
  }

  const behaviors = [...behaviorSet];
  const labels = behaviors.map((behavior) => BEHAVIORS[behavior] || makeLabel(behavior, behavior));
  const hardBlocked = behaviors.some((behavior) => behavior in HARD_BLOCK_BEHAVIORS);
  const denyTier =
    !hardBlocked && behaviors.some((behavior) => behavior in DENY_TIER_BEHAVIORS);

  return { behaviors, labels, hardBlocked, denyTier };
}

/** Analyze a command plus its explicit execution cwd. */
export function analyzeBashOperation(command: string, cwd: string, sessionCwd: string): DangerAnalysis {
  const analysis = analyzeCommand(command);
  if (!isSensitiveWorkingDirectory(cwd, sessionCwd)) return analysis;

  const behaviors = analysis.behaviors.includes("sensitive-working-directory")
    ? analysis.behaviors
    : [...analysis.behaviors, "sensitive-working-directory"];
  const labels = behaviors === analysis.behaviors
    ? analysis.labels
    : [...analysis.labels, BEHAVIORS["sensitive-working-directory"]];
  return { ...analysis, behaviors, labels, hardBlocked: true, denyTier: false };
}
