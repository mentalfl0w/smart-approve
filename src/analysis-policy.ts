/**
 * Decision helpers for one-shot RPC risk analysis.
 * Kept pure so reuse / fallback / spawn-lifetime / text-extraction
 * behavior can be tested without spawning omp.
 */

/** Serialize one RPC prompt behind the previous one. A rejected prior
 *  spawn (e.g. a role alias the host cannot resolve) must not poison
 *  later prompts — swallow it and run the next one. */
export function enqueueSerialized<T>(
  chain: Promise<unknown>,
  run: () => Promise<T>,
): Promise<T> {
  return chain.catch(() => undefined).then(() => run());
}

/** Whether an exiting child's handler may clear the invoker's proc ref.
 *  The exit/error of a superseded child must not clobber a newer one. */
export function shouldClearProcRef(
  current: object | null,
  exiting: object,
): boolean {
  return current === exiting;
}

/** Whether this agent_end should resolve the in-flight prompt.
 *  isTerminal: false means maintenance/async delivery scheduled more
 *  work; only isTerminal !== false is a true run completion. */
export function shouldSettleAgentEnd(frame: { isTerminal?: unknown }): boolean {
  return frame.isTerminal !== false;
}

/** Concatenate text blocks from an RPC message content array. */
function messageText(msg: unknown): string {
  if (!msg || typeof msg !== "object") return "";
  const c = (msg as Record<string, unknown>).content;
  if (typeof c === "string") return c;
  if (!Array.isArray(c)) return "";
  const parts: string[] = [];
  for (const block of c) {
    if (block && typeof block === "object" && "type" in block && "text" in block) {
      const b = block as Record<string, unknown>;
      if (b.type === "text" && typeof b.text === "string") parts.push(b.text);
    }
  }
  return parts.join("");
}

/** Last assistant text from an agent_end messages array, falling back to
 *  text deltas accumulated from message_update frames. The canonical
 *  protocol shape may leave agent_end.messages empty while the actual
 *  text streamed via text_delta events, so the delta buffer is the
 *  reliable fallback for a successful turn. */
export function extractAssistantText(
  messages: unknown,
  deltaBuffer: string,
): string {
  if (Array.isArray(messages)) {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i];
      if (m && typeof m === "object" && (m as Record<string, unknown>).role === "assistant") {
        const t = messageText(m);
        if (t.trim()) return t;
      }
    }
  }
  return deltaBuffer.trim();
}

/** Whether an empty result warrants one retry on a fresh child.
 *  Reuse of a --no-session child can settle without assistant text;
 *  a bounded fresh-child retry recovers that without paying startup
 *  cost on the happy path. Never retry after an abort. */
export function shouldRetryFresh(text: string | null, aborted: boolean): boolean {
  return !text && !aborted;
}
