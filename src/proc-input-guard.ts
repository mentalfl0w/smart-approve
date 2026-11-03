import * as path from "node:path";
import type { ExtensionCtx } from "./types";

export type InteractiveProcessRuntime = "shell" | "python" | "javascript";
export type ProcServiceMode = "session" | "detached" | "persist";

interface ProcService {
  runtime: InteractiveProcessRuntime;
  cwd: string;
  /** Session that last registered the service; used only for shutdown cleanup. */
  sessionId?: string;
  /** Mode selected through `write proc://<name>/mode`; absent = session.
   *  detached/persist outlive owner-session cleanup. */
  lifetime?: ProcServiceMode;
}

export interface TrackedProcInput {
  name: string;
  runtime: InteractiveProcessRuntime;
  command: string;
  cwd: string;
}

const services = new Map<string, ProcService>();

/** Public session id, when the host exposes a stable one. */
export function sessionIdOf(
  ctx: Pick<ExtensionCtx, "sessionManager"> | undefined,
): string | undefined {
  try {
    const id = ctx?.sessionManager?.getSessionId?.();
    return typeof id === "string" && id.trim() ? id.trim() : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Public proc routing is project + name: `write proc://<name>` reaches the
 * project-unique service, not a caller's session-local one. OMP documents
 * named services as project-unique, and the public URI has no session
 * component, so a host that allowed same-name services could not let callers
 * distinguish the actual process owner. Session id is therefore owner
 * metadata (shutdown cleanup), never part of the lookup identity;
 * partitioning by it would hide a cross-session target.
 */
function serviceKey(name: string, workspaceCwd: string): string {
  return `${path.resolve(workspaceCwd)}\0${name}`;
}

const PROC_SERVICE_MODES: Record<string, ProcServiceMode> = {
  session: "session",
  detached: "detached",
  persist: "persist",
};

/** Parse a public `write proc://<name>/mode` request. */
export function procServiceModeChange(
  pathValue: unknown,
  content: unknown,
): { name: string; mode: ProcServiceMode } | undefined {
  if (typeof pathValue !== "string" || typeof content !== "string") return undefined;
  const name = /^proc:\/\/([^/?#]+)\/mode\/?$/.exec(pathValue)?.[1];
  if (!name) return undefined;
  const mode = PROC_SERVICE_MODES[content.trim().toLowerCase()];
  if (mode !== "session" && mode !== "detached" && mode !== "persist") return undefined;
  return { name, mode };
}

/** Apply a public service-lifetime change to a tracked service. */
export function applyProcServiceMode(
  name: string,
  mode: ProcServiceMode,
  workspaceCwd = process.cwd(),
  sessionId?: string,
): boolean {
  const service = services.get(serviceKey(name, workspaceCwd));
  if (!service) return false;
  service.lifetime = mode;
  if (mode === "session") {
    // The session that returns it to session lifetime owns shutdown cleanup.
    const caller = normalizeSessionId(sessionId);
    if (caller) service.sessionId = caller;
  }
  return true;
}

const SHELLS: Record<string, true> = {
  sh: true,
  bash: true,
  zsh: true,
  dash: true,
  csh: true,
  tcsh: true,
  ksh: true,
  fish: true,
};

function shellWords(command: string): string[] {
  const words: string[] = [];
  let word = "";
  let quote: string | undefined;
  let escaped = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      word += ch;
      escaped = false;
    } else if (ch === "\\") {
      escaped = true;
    } else if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else word += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "#" && word === "") {
      // An unquoted # at the start of a word comments out the rest of its line.
      const newline = command.indexOf("\n", i);
      if (newline === -1) break;
      i = newline;
    } else if (/\s/.test(ch)) {
      if (word) words.push(word);
      word = "";
    } else {
      word += ch;
    }
  }
  if (word) words.push(word);
  return words;
}

const SUDO_LONG_VALUE_OPTIONS: Record<string, true> = {
  "--user": true,
  "--group": true,
  "--chdir": true,
  "--host": true,
  "--prompt": true,
  "--role": true,
  "--type": true,
  "--other-user": true,
  "--command-timeout": true,
  "--close-from": true,
};
const SUDO_SHORT_VALUE_OPTIONS: Record<string, true> = {
  u: true, g: true, C: true, D: true, h: true, p: true, r: true, t: true, U: true, T: true,
};

/** Advance past sudo options; report whether -i/-s/--login/--shell was used. */
function skipSudoOptions(words: string[], start: number): { index: number; loginShell: boolean } {
  let index = start;
  let loginShell = false;
  while (index < words.length) {
    const option = words[index];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(option)) {
      index++;
      continue;
    }
    if (option === "--") {
      index++;
      break;
    }
    if (!option.startsWith("-")) break;
    if (option === "--login" || option === "--shell") {
      loginShell = true;
      index++;
      continue;
    }
    if (option.startsWith("--")) {
      index++;
      if (SUDO_LONG_VALUE_OPTIONS[option] === true && index < words.length) index++;
      continue;
    }
    let consumesNext = false;
    for (let i = 1; i < option.length; i++) {
      const flag = option[i];
      if (flag === "i" || flag === "s") loginShell = true;
      if (SUDO_SHORT_VALUE_OPTIONS[flag] === true) {
        consumesNext = i === option.length - 1;
        break;
      }
    }
    index++;
    if (consumesNext && index < words.length) index++;
  }
  return { index, loginShell };
}

/** Remove leading blank lines and full-line shell comments. */
function stripLeadingComments(command: string): string {
  let index = 0;
  while (index < command.length) {
    const ch = command[index];
    if (/\s/.test(ch)) {
      index++;
      continue;
    }
    if (ch === "#") {
      const newline = command.indexOf("\n", index);
      if (newline === -1) return "";
      index = newline + 1;
      continue;
    }
    break;
  }
  return command.slice(index);
}

function executableAndArgs(command: string): { executable: string; args: string[] } | undefined {
  // Only a leading `cd <one literal token>` may be stripped; a greedy match
  // would swallow later command segments. This is classification-only, so
  // common separators after the leading cd are accepted.
  const body = stripLeadingComments(command);
  const cdPrefix = body.match(
    /^\s*cd\s+(?:'[^']*'|"(?:[^"\\]|\\.)*"|[^\s'"&|;<>]+)\s*(?:&&|\|\||;|\r?\n|#[^\n]*(?:\n|$))\s*([\s\S]+)$/,
  );
  const words = shellWords(cdPrefix?.[1] ?? body);
  let index = 0;
  while (index < words.length) {
    const token = words[index];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
      index++;
      continue;
    }
    const executable = path.basename(token).toLowerCase();
    if (executable === "env") {
      index++;
      while (index < words.length) {
        const option = words[index];
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(option)) {
          index++;
          continue;
        }
        if (option === "--") {
          index++;
          break;
        }
        if (!option.startsWith("-")) break;
        index++;
        if (["-u", "--unset", "-C", "--chdir"].includes(option) && index < words.length) index++;
      }
      continue;
    }
    if (["command", "exec", "nohup", "time", "setsid"].includes(executable)) {
      index++;
      if (words[index] === "--") index++;
      continue;
    }
    if (executable === "sudo") {
      const parsed = skipSudoOptions(words, index + 1);
      index = parsed.index;
      // `sudo -i` / `sudo -s` / `sudo --login` / `sudo --shell` with no
      // command starts an interactive shell; a following command is not.
      if (index >= words.length) {
        return parsed.loginShell ? { executable: "sh", args: [] } : undefined;
      }
      continue;
    }
    if (executable === "nice") {
      index++;
      if (words[index] === "-n") index += 2;
      continue;
    }
    return { executable, args: words.slice(index + 1) };
  }
  return undefined;
}


export function classifyInteractiveService(command: string): InteractiveProcessRuntime | undefined {
  const invocation = executableAndArgs(command);
  if (!invocation) return undefined;
  const { executable, args } = invocation;
  const interactive = args.some((arg) =>
    arg === "-i" || arg === "--interactive" || /^-[^-]*i/.test(arg),
  );

  if (SHELLS[executable] === true) {
    const executesInline = args.some((arg) =>
      arg === "-c" || arg === "-e" || arg === "--command" || arg === "--eval" ||
      /^(?:--command|--eval)=/.test(arg) || /^-[^-]*[ce]/.test(arg),
    );
    const hasScript = args.some((arg) => !arg.startsWith("-") && arg !== "--");
    return interactive || (!executesInline && !hasScript) ? "shell" : undefined;
  }

  if (/^(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)$/.test(executable)) {
    const readsStdin = args.includes("-");
    const hasScript = args.some((arg) => !arg.startsWith("-") && arg !== "--");
    return interactive || readsStdin || !hasScript ? "python" : undefined;
  }

  if (/^(?:node(?:js|\d+(?:\.\d+)*)?|bun|deno)$/.test(executable)) {
    const readsStdin = args.includes("-");
    const hasScript = args.some((arg) => !arg.startsWith("-") && arg !== "--");
    return interactive || readsStdin || !hasScript ? "javascript" : undefined;
  }

  return undefined;
}

export function trackInteractiveService(
  name: string,
  command: string,
  cwd: string,
  workspaceCwd = cwd,
  sessionId?: string,
): void {
  const runtime = classifyInteractiveService(command);
  const key = serviceKey(name, workspaceCwd);
  const owner = normalizeSessionId(sessionId);
  if (runtime) {
    services.set(key, owner ? { runtime, cwd, sessionId: owner } : { runtime, cwd });
    return;
  }
  // A named-service call replaces the project-unique process with the new
  // spec. A non-REPL replacement must not inherit the previous classifier.
  services.delete(key);
}

export function getTrackedServiceCwd(
  name: string,
  workspaceCwd = process.cwd(),
): string | undefined {
  return services.get(serviceKey(name, workspaceCwd))?.cwd;
}

export function setTrackedServiceCwd(
  name: string,
  cwd: string,
  workspaceCwd = process.cwd(),
): void {
  const service = services.get(serviceKey(name, workspaceCwd));
  if (service) service.cwd = cwd;
}

export function forgetProcService(
  name: string,
  workspaceCwd = process.cwd(),
  sessionId?: string,
): void {
  const key = serviceKey(name, workspaceCwd);
  const service = services.get(key);
  if (!service) return;
  // Explicit exits/kills are authoritative. Detached/persist services can be
  // observed by any session; session-lifetime registrations are only cleared
  // by their owner so a stale result cannot untrack a newer live service.
  if (sessionId !== undefined) {
    const caller = normalizeSessionId(sessionId);
    const retained = service.lifetime === "detached" || service.lifetime === "persist";
    if (!retained && service.sessionId !== undefined && service.sessionId !== caller) return;
  }
  services.delete(key);
}

/** Drop every registration owned by the ending session. */
export function forgetSessionServices(sessionId: string | undefined): void {
  const owner = normalizeSessionId(sessionId);
  if (!owner) return;
  for (const [key, service] of services) {
    if (
      service.sessionId === owner &&
      service.lifetime !== "detached" &&
      service.lifetime !== "persist"
    ) {
      services.delete(key);
    }
  }
}

export function procServiceKillName(pathValue: unknown): string | undefined {
  if (typeof pathValue !== "string") return undefined;
  return /^proc:\/\/([^/?#]+)\/kill\/?$/.exec(pathValue)?.[1];
}

export function resolveTrackedServiceInput(
  pathValue: unknown,
  content: unknown,
  workspaceCwd = process.cwd(),
  sessionId?: string,
): TrackedProcInput | undefined {
  if (typeof pathValue !== "string" || typeof content !== "string" || !content.trim()) return undefined;
  const name = /^proc:\/\/([^/?#]+)\/?$/.exec(pathValue)?.[1];
  if (!name) return undefined;
  const service = services.get(serviceKey(name, workspaceCwd));
  if (!service) return undefined;
  // Public routing is by project + name, so a caller from another session
  // still targets this service; never treat it as unknown input. A caller
  // may adopt a legacy unowned registration so shutdown can clean it up.
  const caller = normalizeSessionId(sessionId);
  if (service.sessionId === undefined && caller !== undefined) {
    service.sessionId = caller;
  }
  return { name, runtime: service.runtime, command: content, cwd: service.cwd };
}

function normalizeSessionId(sessionId: string | undefined): string | undefined {
  const value = sessionId?.trim();
  return value ? value : undefined;
}
