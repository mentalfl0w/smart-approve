import { test } from "node:test";
import assert from "node:assert/strict";
import { getBundledModel } from "@oh-my-pi/pi-catalog/models";
import { getI18n } from "./i18n.ts";
import { OmpNativeJudgeDecisionAdapter } from "./omp-native-judge-adapter.ts";
import type { OmpNativeJudgmentSupport } from "./omp-native-judge-adapter.ts";
import { NativeDecisionProtocol } from "./native-decision-protocol.ts";
import type { NativeDecisionInput } from "./native-decision-protocol.ts";
import type { HostModelRegistry } from "./types.ts";
import type { LoggerLike } from "./logger.ts";

const input: NativeDecisionInput = {
  subject: "git push --force origin feature",
  subjectLabel: "Shell command",
  behaviorLabels: ["force-push"],
  contextSection: "The user asked to publish a feature branch.",
};
const translations = getI18n("en");
const silentLogger: LoggerLike = { log() {} };

test("OMP native judge reuses registry credentials and preserves high risk", async () => {
  const model = getBundledModel("openrouter", "~typesafe/jev-latest");
  let receivedConnection: { apiKey: unknown; headers?: Record<string, string> } | undefined;
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => ({ "x-model-route": "catalog" }),
  };
  const support: OmpNativeJudgmentSupport = {
    isJudgmentApi: (api) => api === model.api,
    createNativeJudge: (selectedModel, connection) => {
      assert.equal(selectedModel, model);
      receivedConnection = connection;
      return {
        judge: async () => ({
          answers: {
            risk: { type: "choice", choice: "high" },
            recommend: { type: "choice", choice: "allow" },
          },
        }),
      };
    },
  };
  const adapter = new OmpNativeJudgeDecisionAdapter(
    new NativeDecisionProtocol(),
    1_000,
    silentLogger,
    async () => support,
  );

  assert.deepEqual(
    await adapter.tryAnalyze(registry, `${model.provider}/${model.id}`, input, translations),
    { matched: true, analysis: { risk: "high", recommend: "allow" } },
  );
  assert.deepEqual(receivedConnection, {
    apiKey: "registry-token",
    headers: { "x-model-route": "catalog" },
  });
});

test("OMP versions without createNativeJudge keep judgment models unavailable instead of sending them to chat", async () => {
  const model = getBundledModel("openrouter", "~typesafe/jev-latest");
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => undefined,
  };
  const adapter = new OmpNativeJudgeDecisionAdapter(
    new NativeDecisionProtocol(),
    1_000,
    silentLogger,
    async () => ({ isJudgmentApi: () => true }),
  );

  assert.deepEqual(
    await adapter.tryAnalyze(registry, `${model.provider}/${model.id}`, input, translations),
    { matched: true, analysis: null },
  );
});

test("OMP judgment API fallback recognizes native API when isJudgmentApi is absent", async () => {
  const bundledModel = getBundledModel("openrouter", "~typesafe/jev-latest");
  const model = { ...bundledModel, kind: undefined };
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => undefined,
  };
  const adapter = new OmpNativeJudgeDecisionAdapter(
    new NativeDecisionProtocol(),
    1_000,
    silentLogger,
    async () => ({}),
  );

  assert.deepEqual(
    await adapter.tryAnalyze(registry, `${model.provider}/${model.id}`, input, translations),
    { matched: true, analysis: null },
  );
});

test("OMP native timeout aborts the judge and returns no verdict", async () => {
  const model = getBundledModel("openrouter", "~typesafe/jev-latest");
  let judgeSignal: AbortSignal | undefined;
  const pendingJudgment = Promise.withResolvers<{ answers: unknown }>();
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => undefined,
  };
  const support: OmpNativeJudgmentSupport = {
    isJudgmentApi: () => true,
    createNativeJudge: () => ({
      judge: async (_request, options) => {
        judgeSignal = options?.signal;
        return pendingJudgment.promise;
      },
    }),
  };
  const adapter = new OmpNativeJudgeDecisionAdapter(
    new NativeDecisionProtocol(),
    10,
    silentLogger,
    async () => support,
  );

  assert.deepEqual(
    await adapter.tryAnalyze(registry, `${model.provider}/${model.id}`, input, translations),
    { matched: true, analysis: null },
  );
  assert.equal(judgeSignal?.aborted, true);
});
