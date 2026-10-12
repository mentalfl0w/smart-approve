import { test } from "node:test";
import assert from "node:assert/strict";
import { getI18n } from "./i18n.ts";
import { PiClassifierDecisionAdapter } from "./pi-classifier-adapter.ts";
import { NativeDecisionProtocol } from "./native-decision-protocol.ts";
import type { NativeDecisionInput } from "./native-decision-protocol.ts";
import type { LoggerLike } from "./logger.ts";

const input: NativeDecisionInput = {
  subject: "git push --force origin feature",
  subjectLabel: "Shell command",
  behaviorLabels: ["force-push"],
  contextSection: "The user asked to publish a feature branch.",
};
const translations = getI18n("en");
const silentLogger: LoggerLike = { log() {} };

test("Pi classifier adapter maps registered classifier answers", async () => {
  const classifierModel = { id: "jev-latest", provider: "typesafe", type: "classifier" };
  const registry = {
    getModelOfType(type: string, provider: string, modelId: string) {
      assert.equal(type, "classifier");
      assert.equal(provider, "typesafe");
      assert.equal(modelId, "jev-latest");
      return classifierModel;
    },
    async classify(model: unknown) {
      assert.equal(model, classifierModel);
      return {
        stopReason: "stop",
        answers: {
          risk: { type: "choice", choice: "medium", probabilities: {}, confidence: 1 },
          recommend: { type: "choice", choice: "allow", probabilities: {}, confidence: 1 },
        },
      };
    },
  };
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 1_000, silentLogger);

  assert.deepEqual(
    await adapter.tryAnalyze(registry, "typesafe/jev-latest", input, translations),
    { matched: true, analysis: { risk: "medium", recommend: "allow" } },
  );
});

test("Pi classifier errors do not produce an approval result", async () => {
  const registry = {
    getModelOfType: () => ({ id: "jev-latest", provider: "typesafe", type: "classifier" }),
    classify: async () => ({
      stopReason: "error",
      errorMessage: "account unavailable",
      answers: {},
    }),
  };
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 1_000, silentLogger);

  assert.deepEqual(
    await adapter.tryAnalyze(registry, "typesafe/jev-latest", input, translations),
    { matched: true, analysis: null },
  );
});

test("Pi classifier lookup errors leave the model unmatched", async () => {
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 1_000, silentLogger);
  const registry = {
    getModelOfType() {
      throw new Error("registry unavailable");
    },
  };

  assert.deepEqual(
    await adapter.tryAnalyze(registry, "typesafe/jev-latest", input, translations),
    { matched: false },
  );
});

test("Pi registered classifiers without classify() return no verdict", async () => {
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 1_000, silentLogger);
  const registry = { getModelOfType: () => ({ id: "jev-latest" }) };

  assert.deepEqual(
    await adapter.tryAnalyze(registry, "typesafe/jev-latest", input, translations),
    { matched: true, analysis: null },
  );
});

test("Pi classifier request rejection returns no verdict", async () => {
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 1_000, silentLogger);
  const registry = {
    getModelOfType: () => ({ id: "jev-latest" }),
    classify: async () => {
      throw new Error("provider request failed");
    },
  };

  assert.deepEqual(
    await adapter.tryAnalyze(registry, "typesafe/jev-latest", input, translations),
    { matched: true, analysis: null },
  );
});

test("Pi classifier cancellation aborts the underlying request", async () => {
  const pendingClassification = Promise.withResolvers<unknown>();
  let requestSignal: AbortSignal | undefined;
  const registry = {
    getModelOfType: () => ({ id: "jev-latest" }),
    classify: async (_model: unknown, _context: unknown, options?: { signal?: AbortSignal }) => {
      requestSignal = options?.signal;
      return pendingClassification.promise;
    },
  };
  const adapter = new PiClassifierDecisionAdapter(new NativeDecisionProtocol(), 0, silentLogger);
  const controller = new AbortController();
  const pending = adapter.tryAnalyze(
    registry,
    "typesafe/jev-latest",
    input,
    translations,
    controller.signal,
  );
  controller.abort();

  assert.deepEqual(await pending, { matched: true, analysis: null });
  assert.equal(requestSignal?.aborted, true);
});
