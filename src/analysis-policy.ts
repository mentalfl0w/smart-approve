/**
 * Decision helpers for one-shot RPC risk analysis.
 * Kept pure so the reuse / fallback / spawn-lifetime bugs can be tested
 * without spawning omp.
 */

/** Models to try for one analysis, in order. */
export function analysisModelChain(model: string): string[] {
  return [model];
}

/** Serialize one RPC prompt behind the previous one. */
export function enqueueSerialized<T>(
  chain: Promise<unknown>,
  run: () => Promise<T>,
): Promise<T> {
  return chain.catch(() => undefined).then(() => run());
}

/** Whether the existing RPC child may handle this prompt. */
export function shouldReuseRpcChild(
  _model: string,
  _currentModel: string | null,
  _isAlive: boolean,
): boolean {
  return false;
}

/** Whether an exiting child's handler may clear the invoker's proc ref. */
export function shouldClearProcRef(
  current: object | null,
  exiting: object,
): boolean {
  return current === exiting;
}

/** Whether this agent_end should resolve the in-flight prompt. */
export function shouldSettleAgentEnd(frame: { isTerminal?: boolean }): boolean {
  return frame.isTerminal !== false;
}
