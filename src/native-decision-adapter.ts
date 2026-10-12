import type { LoggerLike } from "./logger";
import type { RiskAnalysis } from "./types";
import type { NativeDecisionProtocol } from "./native-decision-protocol";

export interface QualifiedModelSelector {
  provider: string;
  modelId: string;
}

export type NativeDecisionAttempt =
  | { matched: false }
  | { matched: true; analysis: RiskAnalysis | null };

/** Shared host-neutral selector parsing and cancellation/deadline lifecycle. */
export class NativeDecisionAdapter {
  constructor(
    protected readonly protocol: NativeDecisionProtocol,
    protected readonly timeoutMs: number,
    protected readonly logger: LoggerLike,
  ) {}

  protected parseSelector(selector: string): QualifiedModelSelector | null {
    const separator = selector.indexOf("/");
    if (separator <= 0 || separator === selector.length - 1) return null;
    return {
      provider: selector.slice(0, separator),
      modelId: selector.slice(separator + 1),
    };
  }

  protected async runWithDeadline<T>(
    signal: AbortSignal | undefined,
    run: (signal: AbortSignal) => Promise<T>,
  ): Promise<T | null> {
    const controller = new AbortController();
    const cancellation = Promise.withResolvers<null>();
    const abort = (): void => {
      if (controller.signal.aborted) return;
      controller.abort();
      cancellation.resolve(null);
    };
    const onParentAbort = (): void => abort();
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", onParentAbort, { once: true });
    const timer = this.timeoutMs > 0 && !controller.signal.aborted
      ? setTimeout(abort, this.timeoutMs)
      : undefined;

    try {
      if (controller.signal.aborted) return null;
      const operation = Promise.resolve().then(() => run(controller.signal));
      const result = await Promise.race([operation, cancellation.promise]);
      return controller.signal.aborted ? null : result;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onParentAbort);
      abort();
    }
  }
}
