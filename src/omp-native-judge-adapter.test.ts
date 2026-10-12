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

test("OMP's built-in loader uses the real NativeJudge transport", async () => {
  const baseModel = getBundledModel("openrouter", "~typesafe/jev-latest");
  let requestPath = "";
  let authorization = "";
  let routeHeader = "";
  let requestModel = "";
  let questionNames: string[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      requestPath = new URL(request.url).pathname;
      authorization = request.headers.get("authorization") ?? "";
      routeHeader = request.headers.get("x-model-route") ?? "";
      const body: unknown = await request.json();
      if (
        typeof body === "object"
        && body !== null
        && "model" in body
        && typeof body.model === "string"
      ) {
        requestModel = body.model;
      }
      if (
        typeof body === "object"
        && body !== null
        && "questions" in body
        && typeof body.questions === "object"
        && body.questions !== null
      ) {
        questionNames = Object.keys(body.questions);
      }
      return Response.json({
        model: "local-native-judge",
        answers: {
          risk: { type: "choice", choice: "high", probabilities: { low: 0, medium: 0.1, high: 0.9 }, confidence: 0.9 },
          recommend: { type: "choice", choice: "deny", probabilities: { allow: 0.05, deny: 0.95 }, confidence: 0.95 },
        },
        usage: { input_tokens: 11, output_tokens: 0, cost: 0 },
      });
    },
  });
  const model = {
    ...baseModel,
    baseUrl: `http://127.0.0.1:${server.port}/api/alpha`,
  };
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "local-token",
    resolveModelHeaders: async () => ({ "x-model-route": "catalog" }),
  };
  const adapter = new OmpNativeJudgeDecisionAdapter(new NativeDecisionProtocol(), 5_000, silentLogger);

  try {
    assert.deepEqual(
      await adapter.tryAnalyze(registry, `${model.provider}/${model.id}`, input, translations),
      { matched: true, analysis: { risk: "high", recommend: "deny" } },
    );
    assert.equal(requestPath, "/api/alpha/decisions");
    assert.equal(authorization, "Bearer local-token");
    assert.equal(routeHeader, "catalog");
    assert.equal(requestModel, model.id);
    assert.deepEqual(questionNames.sort(), ["recommend", "risk"]);
  } finally {
    server.stop(true);
  }
});
