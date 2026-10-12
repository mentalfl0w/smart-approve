import type { HostModelRegistry } from "./types";
import type { I18n } from "./i18n";
import type { LoggerLike } from "./logger";
import { NativeDecisionAdapter, type NativeDecisionAttempt } from "./native-decision-adapter";
import { NativeDecisionProtocol, type NativeDecisionInput } from "./native-decision-protocol";

/** Uses Pi's authenticated classifier registry when the selector is a classifier model. */
export class PiClassifierDecisionAdapter extends NativeDecisionAdapter {
  constructor(protocol: NativeDecisionProtocol, timeoutMs: number, logger: LoggerLike) {
    super(protocol, timeoutMs, logger);
  }

  async tryAnalyze(
    registry: HostModelRegistry | undefined,
    modelSpec: string,
    input: NativeDecisionInput,
    t: I18n,
    signal?: AbortSignal,
  ): Promise<NativeDecisionAttempt> {
    const selected = this.parseSelector(modelSpec);
    if (!registry?.getModelOfType || !selected) return { matched: false };

    let model: unknown;
    try {
      model = registry.getModelOfType("classifier", selected.provider, selected.modelId);
    } catch (e) {
      this.logger.log(`Pi classifier model lookup failed: ${e instanceof Error ? e.message : String(e)}`);
      return { matched: false };
    }
    if (model === undefined || model === null) return { matched: false };
    if (typeof registry.classify !== "function") {
      this.logger.log("Pi classifier model is registered but classify() is unavailable");
      return { matched: true, analysis: null };
    }

    try {
      const result = await this.runWithDeadline(signal, (requestSignal) =>
        registry.classify!(model, {
          state: this.protocol.state(input),
          questions: this.protocol.questions(t),
        }, {
          signal: requestSignal,
          ...(this.timeoutMs > 0 ? { timeoutMs: this.timeoutMs } : {}),
        }),
      );
      if (
        typeof result === "object"
        && result !== null
        && !Array.isArray(result)
        && "stopReason" in result
        && result.stopReason !== "stop"
      ) {
        const error = "errorMessage" in result ? result.errorMessage : undefined;
        this.logger.log(`Pi classifier failed: ${typeof error === "string" ? error : String(result.stopReason)}`);
        return { matched: true, analysis: null };
      }
      const analysis = this.protocol.parse(result);
      if (!analysis) this.logger.log("Pi classifier returned an invalid answer");
      return { matched: true, analysis };
    } catch (e) {
      this.logger.log(`Pi classifier failed: ${e instanceof Error ? e.message : String(e)}`);
      return { matched: true, analysis: null };
    }
  }
}
