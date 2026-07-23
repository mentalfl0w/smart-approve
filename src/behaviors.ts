/**
 * Smart Approve — behavior detection.
 *
 * Behavior-based detection parses command arguments (not just regex) so
 * evasions like `git push origin +branch` are still flagged.  Each behavior
 * has a canonical id and localized description.  Regex-based DANGER_RULES
 * are retained as a secondary net for patterns that don't fit the parser
 * model (fork bombs, curl|sh, block-device writes, etc.).
 */

import type { DangerAnalysis } from "./types";
import { makeLabel } from "./i18n";

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
  "sudo": makeLabel("sudo command", "sudo 命令"),
  "docker-destroy": makeLabel("docker rm/rmi/volume/network rm", "docker 删除容器/镜像/卷"),
  "kubectl-delete": makeLabel("kubectl delete", "kubectl delete"),
  "mv-sys-dir": makeLabel("Move system directory", "移动系统目录"),
  "cp-root": makeLabel("Recursive copy to root", "递归拷贝到根"),
};

// ── Regex danger rules (secondary net) ──────────────────────────────
//
// Patterns that don't fit the git-arg parser model.  Each maps to a behavior
// id from BEHAVIORS so the caller sees a unified {behaviors, rule} result.

const DANGER_RULES: Array<{ pattern: RegExp; behavior: string }> = [
  // — Recursive force delete —
  { pattern: /(?:^|[\s;&|])rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/,
    behavior: "recursive-force-delete" },
  { pattern: /\brmdir\s+(?:-[a-zA-Z]*p[a-zA-Z]*)?\s*\//,
    behavior: "recursive-force-delete" },

  // — Root / system directories —
  { pattern: /\brm\b.*\s\/(?:\s|$)/, behavior: "delete-root" },
  { pattern: /\brm\b.*\s\/(?:usr|etc|var|bin|sbin|boot|dev|proc|sys|root|home|Library)\b/,
    behavior: "delete-sys-dir" },

  // — Fork bomb / resource exhaustion —
  { pattern: /:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:/, behavior: "fork-bomb" },
  { pattern: /\b(?:fork|bomb)\b.*\&\s*\|.*\&/, behavior: "fork-bomb" },

  // — Remote fetch-and-execute (curl/wget | sh) —
  { pattern: /\b(?:curl|wget|fetch)\b.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|python|python3|perl|ruby|node)\b/,
    behavior: "remote-fetch-exec" },
  { pattern: /\b(?:curl|wget)\b.*(?:\|\s*sh|\|\s*bash)/, behavior: "remote-fetch-exec" },

  // — Write to system-sensitive files / raw block devices —
  { pattern: /(?:>|>>)\s*\/(?:etc\/(?:passwd|shadow|sudoers|hosts)|proc|sys|dev\/(?:sd[a-z]\d*|nvme\d|disk\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk|mapper\/|md\d|sg\d|st\d|nst\d))/,
    behavior: "write-sensitive-file" },
  { pattern: /(?:>|>>)\s*\/dev\/(?:sd[a-z]\d*|nvme\d|disk\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk|mapper\/|md\d|sg\d|st\d|nst\d)/,
    behavior: "write-block-device" },
  { pattern: /\b(?:chmod|chown|chgrp)\b.*\s\/(?:etc|usr|var|bin|sbin|boot)\b/,
    behavior: "chmod-sys-dir" },

  // — Shutdown / reboot —
  { pattern: /\b(?:shutdown|poweroff|halt|reboot|init\s+0|init\s+6)\b/, behavior: "shutdown-reboot" },
  { pattern: /\bsudo\s+(?:shutdown|poweroff|halt|reboot|init)\b/, behavior: "shutdown-reboot" },

  // — Disk format / raw write —
  { pattern: /\b(?:mkfs|dd)\b.*(?:of=)?\/dev\/(?:sd[a-z]\d*|nvme\d|disk\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk|mapper\/|md\d|sg\d|st\d|nst\d)/,
    behavior: "disk-format" },
  { pattern: /\b(?:mount|umount)\b.*\s\/dev\/(?:sd|nvme|disk)/, behavior: "mount-block-device" },

  // — Kill processes (pkill -9 / killall) —
  { pattern: /\b(?:pkill|killall)\s+(?:-[a-zA-Z]*9|-\d+)\s+/, behavior: "force-kill" },
  { pattern: /\bkill\s+-9\b/, behavior: "force-kill" },

  // — Package manager global uninstall —
  { pattern: /\b(?:npm|pnpm|yarn)\s+(?:uninstall|remove|rm)\s+(?:-[a-zA-Z]*g[a-zA-Z]*)\b/,
    behavior: "pkg-global-uninstall" },
  { pattern: /\bpip3?\s+uninstall\b/, behavior: "pkg-global-uninstall" },

  // — Git destructive operations (parser-unfriendly patterns) —
  { pattern: /\bgit\s+push\b.*(?:\s-f\b|--force(?:-with-lease)?\b|--mirror\b)/,
    behavior: "git-force-push" },
  { pattern: /\bgit\s+push\b.*--delete\b/, behavior: "git-push-delete" },
  { pattern: /\bgit\s+push\s+\S+\s+:[^\s]/, behavior: "git-push-colon-ref" },
  { pattern: /\bgit\s+reset\b.*--hard\b/, behavior: "git-hard-reset" },
  { pattern: /\bgit\s+reset\s+-[a-zA-Z]*H/, behavior: "git-hard-reset" },
  { pattern: /\bgit\s+clean\s+-[a-zA-Z]*f/, behavior: "git-clean" },
  { pattern: /\bgit\s+branch\s+-[a-zA-Z]*D\b/, behavior: "git-branch-delete" },
  { pattern: /\bgit\s+tag\s+(?:-d\b|--delete\b)/, behavior: "git-tag-delete" },
  { pattern: /\bgit\s+stash\s+clear\b/, behavior: "git-stash-clear" },
  { pattern: /\bgit\s+stash\s+drop\b/, behavior: "git-stash-drop" },
  { pattern: /\bgit\s+reflog\s+expire\b/, behavior: "git-reflog-expire" },
  { pattern: /\bgit\s+gc\b.*--prune/, behavior: "git-gc-prune" },
  { pattern: /\bgit\s+filter-branch\b/, behavior: "git-filter-branch" },
  { pattern: /\bgit\s+filter-repo\b/, behavior: "git-filter-repo" },
  { pattern: /\bgit\s+commit\b.*--amend\b/, behavior: "git-commit-amend" },
  { pattern: /\bgit\s+rebase\b(?!\s+--(?:abort|continue|skip)\b)/, behavior: "git-rebase" },
  { pattern: /\bgit\s+remote\s+(?:rm|remove)\b/, behavior: "git-remote-rm" },
  { pattern: /\bgit\s+submodule\s+deinit\b/, behavior: "git-submodule-deinit" },
  { pattern: /\bgit\s+worktree\s+remove\b/, behavior: "git-worktree-remove" },
  { pattern: /\bgit\s+update-ref\b.*(?:-d\b|--delete\b)/, behavior: "git-update-ref-delete" },
  { pattern: /\bgit\s+(?:checkout|restore)\s+--\s*\./, behavior: "git-checkout-discard" },
  { pattern: /\bgit\s+restore\s+(?:\.|--worktree\b)/, behavior: "git-restore-discard" },
  { pattern: /\bgit\s+config\b.*--global\b/, behavior: "git-config-global" },
  { pattern: /\bgit\s+notes\b.*\bremove\b/, behavior: "git-notes-remove" },

  // — sudo prefix —
  { pattern: /\bsudo\s+/, behavior: "sudo" },

  // — Container destruction / image deletion —
  { pattern: /\bdocker\s+(?:rm|rmi|volume\s+rm|network\s+rm)\b/, behavior: "docker-destroy" },
  { pattern: /\bkubectl\s+delete\b/, behavior: "kubectl-delete" },

  // — Filesystem operations —
  { pattern: /\bmv\b.*\s\/(?:usr|etc|var|bin)\b/, behavior: "mv-sys-dir" },
  { pattern: /\bcp\s+-r\b.*\s\/\s*$/, behavior: "cp-root" },
];

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

function extractLeadingArgs(tokens: string[], executable: string): string[] | null {
  const idx = tokens.findIndex((t) => t === executable);
  if (idx === -1) return null;
  const after = tokens.slice(idx + 1);
  const stopOps = new Set(["|", "||", "&&", ";", "&", "(", ")", "{", "}", "<", ">"]);
  const end = after.findIndex((t) => stopOps.has(t));
  return end === -1 ? after : after.slice(0, end);
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
    if (arg === "-f" || arg === "--force") return true;
    if (arg === "--force-with-lease" || arg.startsWith("--force-with-lease=")) return true;
    if (arg === "--force-if-includes") return true;
    if (arg.startsWith("+") && arg.length > 1 && !arg.startsWith("+-")) return true;
  }
  return false;
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

/** Detect git behaviors by parsing arguments. Returns behavior ids. */
function analyzeGit(args: string[]): string[] {
  const skipped = skipGitGlobalOptions(args);
  if (!skipped) return [];
  const { subcommand, rest } = skipped;
  switch (subcommand) {
    case "push":
      return isForcePush(rest) ? ["git-force-push"] : [];
    case "branch":
      return isBranchDelete(rest) ? ["git-branch-delete"] : [];
    case "worktree":
      return (rest[0] === "remove" || rest[0] === "rm") ? ["git-worktree-remove"] : [];
    case "reset":
      return rest.includes("--hard") ? ["git-hard-reset"] : [];
    case "clean":
      return isGitCleanDestructive(rest) ? ["git-clean"] : [];
    default:
      return [];
  }
}

// ── Composite analysis ───────────────────────────────────────────────

/** Behaviors that are always hard-blocked (no LLM review, no allow). */
const HARD_BLOCK_BEHAVIORS = new Set([
  "delete-root",
  "fork-bomb",
  "remote-fetch-exec",
  "write-sensitive-file",
  "write-block-device",
  "disk-format",
  "shutdown-reboot",
]);

/** Normalize command for stable regex matching. */
export function normalize(cmd: string): string {
  return String(cmd ?? "")
    .replace(/#.*$/, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Analyze a bash command for dangerous behaviors.
 * Combines git-arg parsing with regex rules for a unified result.
 */
export function analyzeCommand(cmd: string): DangerAnalysis {
  const c = normalize(cmd);
  const behaviorSet = new Set<string>();

  // 1. Git argument parsing
  const tokens = roughTokenize(c);
  const gitArgs = extractLeadingArgs(tokens, "git");
  if (gitArgs) {
    for (const b of analyzeGit(gitArgs)) behaviorSet.add(b);
  }

  // 2. Regex rules (secondary net)
  for (const rule of DANGER_RULES) {
    if (rule.pattern.test(c)) behaviorSet.add(rule.behavior);
  }

  const behaviors = [...behaviorSet];
  const labels = behaviors.map((b) => BEHAVIORS[b] || makeLabel(b, b));
  const hardBlocked = behaviors.some((b) => HARD_BLOCK_BEHAVIORS.has(b));

  return { behaviors, labels, hardBlocked };
}
