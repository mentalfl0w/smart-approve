import type {
  Api,
  ApiKey,
  JudgmentRequest,
  Model,
  NativeJudgeConnection,
  Questions,
} from "@oh-my-pi/pi-ai";
import type { HostModelRegistry } from "./types";
import type { I18n } from "./i18n";
import type { LoggerLike } from "./logger";
import { NativeDecisionAdapter, type NativeDecisionAttempt } from "./native-decision-adapter";
import { NativeDecisionProtocol, type NativeDecisionInput } from "./native-decision-protocol";

/** Judgment APIs supported by OMP's NativeJudge when the host lacks its predicate export. */
const KNOWN_JUDGMENT_APIS: Readonly<Record<string, true>> = Object.freeze({
  typesafe: true,
  "openrouter-decisions": true,
  "openai-decisions": true,
  "workers-ai-systemone": true,
});

export interface OmpNativeJudgmentSupport {
  isJudgmentApi?: (api: Api) => boolean;
  createNativeJudge?: (
    model: Model<Api>,
    connection: NativeJudgeConnection,
  ) => {
    judge: (
      request: JudgmentRequest<Questions>,
      options?: { signal?: AbortSignal },
    ) => Promise<{ answers: unknown }>;
  };
}

export type OmpNativeJudgmentSupportLoader = () => Promise<OmpNativeJudgmentSupport | null>;

/** Uses OMP's registry credentials and native judge without loading them in Pi. */
export class OmpNativeJudgeDecisionAdapter extends NativeDecisionAdapter {
  private supportPromise?: Promise<OmpNativeJudgmentSupport | null>;
  private readonly supportLoader: OmpNativeJudgmentSupportLoader;

  constructor(
    protocol: NativeDecisionProtocol,
    timeoutMs: number,
    logger: LoggerLike,
    supportLoader?: OmpNativeJudgmentSupportLoader,
  ) {
    super(protocol, timeoutMs, logger);
    this.supportLoader = supportLoader ?? (() => this.loadSupport());
  }

  async tryAnalyze(
    registry: HostModelRegistry | undefined,
    modelSpec: string,
    input: NativeDecisionInput,
    t: I18n,
    signal?: AbortSignal,
  ): Promise<NativeDecisionAttempt> {
    const selected = this.parseSelector(modelSpec);
    if (!registry?.find || !selected) return { matched: false };

    let model: Model<Api> | undefined;
    try {
      model = registry.find(selected.provider, selected.modelId);
    } catch (e) {
      this.logger.log(`OMP model lookup failed: ${e instanceof Error ? e.message : String(e)}`);
      return { matched: false };
    }
    if (!model) return { matched: false };

    // OMP marks judgment rows with `kind: "judge"`; other known kinds are not
    // decision models, so they keep the chat path without loading the host API.
    const modelHasKind = "kind" in model && typeof model.kind === "string";
    const isJudgeModel = "kind" in model && model.kind === "judge";
    if (modelHasKind && !isJudgeModel) return { matched: false };
    if (!registry.resolver || !registry.resolveModelHeaders) {
      return isJudgeModel ? { matched: true, analysis: null } : { matched: false };
    }

    let support: OmpNativeJudgmentSupport | null;
    try {
      support = await this.supportLoader();
    } catch (e) {
      this.logger.log(`OMP native judgment API load failed: ${e instanceof Error ? e.message : String(e)}`);
      support = null;
    }

    let nativeApi = isJudgeModel;
    try {
      if (support?.isJudgmentApi) nativeApi = support.isJudgmentApi(model.api);
      else if (!nativeApi) nativeApi = Object.hasOwn(KNOWN_JUDGMENT_APIS, model.api);
    } catch (e) {
      this.logger.log(`OMP native judgment API lookup failed: ${e instanceof Error ? e.message : String(e)}`);
      return isJudgeModel ? { matched: true, analysis: null } : { matched: false };
    }
    if (!nativeApi) return { matched: false };
    if (!support?.createNativeJudge) {
      this.logger.log(`OMP judgment model ${selected.provider}/${selected.modelId} has no native factory`);
      return { matched: true, analysis: null };
    }

    try {
      const apiKey: ApiKey = registry.resolver(model);
      const result = await this.runWithDeadline(signal, async (requestSignal) => {
        const headers = await registry.resolveModelHeaders!(model, requestSignal);
        if (requestSignal.aborted) return null;
        const judge = support.createNativeJudge!(model, { apiKey, headers });
        return judge.judge({
          state: this.protocol.state(input),
          questions: this.protocol.questions(t),
        }, { signal: requestSignal });
      });
      const analysis = this.protocol.parse(result);
      if (!analysis) this.logger.log("OMP native judge returned no valid analysis");
      return { matched: true, analysis };
    } catch (e) {
      this.logger.log(`OMP native judgment failed: ${e instanceof Error ? e.message : String(e)}`);
      return { matched: true, analysis: null };
    }
  }

  private loadSupport(): Promise<OmpNativeJudgmentSupport | null> {
    this.supportPromise ??= import("@oh-my-pi/pi-ai")
      .then((module) => ({
        isJudgmentApi: typeof module.isJudgmentApi === "function"
          ? module.isJudgmentApi
          : undefined,
        createNativeJudge: typeof module.createNativeJudge === "function"
          ? module.createNativeJudge
          : undefined,
      }))
      .catch(() => null);
    return this.supportPromise;
  }
}
