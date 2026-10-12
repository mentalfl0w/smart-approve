import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeNativeDecision, parseNativeAnswers } from "./native-decisions.ts";
import type { NativeDecisionInput } from "./native-decisions.ts";
import type { JudgmentModel, JudgmentModelRegistry } from "./types.ts";
import type { LoggerLike } from "./logger.ts";

const MODEL: JudgmentModel = {
  id: "openai/gpt-6-luna-decisions",
  provider: "openrouter",
  api: "openrouter-decisions",
  kind: "judge",
};

const INPUT: NativeDecisionInput = {
  subject: "printf 'hello' > ./output.txt",
  subjectLabel: "Command",
  behaviorLabels: ["writes files"],
  contextSection: "Original task: save the generated greeting to output.txt.",
};

const silentLogger: LoggerLike = { log() {} };


const VALID_RISK = { type: "choice", choice: "medium" };
const VALID_RECOMMEND = { type: "choice", choice: "allow" };

const INVALID_ANSWERS: Array<{ name: string; answers: unknown }> = [
  { name: "missing risk", answers: { recommend: VALID_RECOMMEND } },
  { name: "missing recommendation", answers: { risk: VALID_RISK } },
  { name: "a non-choice risk discriminant", answers: { risk: { type: "score", score: 1 }, recommend: VALID_RECOMMEND } },
  { name: "a non-choice recommendation discriminant", answers: { risk: VALID_RISK, recommend: { type: "noul", noul: 0.1 } } },
  { name: "an out-of-domain risk", answers: { risk: { type: "choice", choice: "critical" }, recommend: VALID_RECOMMEND } },
  { name: "a non-exact risk value", answers: { risk: { type: "choice", choice: "HIGH" }, recommend: VALID_RECOMMEND } },
  { name: "an out-of-domain recommendation", answers: { risk: VALID_RISK, recommend: { type: "choice", choice: "approve" } } },
  { name: "a refusal", answers: { risk: { type: "refusal" }, recommend: VALID_RECOMMEND } },
  { name: "a non-object answer map", answers: null },
];

for (const { name, answers } of INVALID_ANSWERS) {
  test(`returns no analysis for ${name}`, () => {
    assert.equal(parseNativeAnswers(answers), null);
  });
}

test("extension deadline bounds pending model-header resolution", async () => {
  let headerSignal: AbortSignal | undefined;
  const registry: JudgmentModelRegistry = {
    resolver: () => "registry-key",
    resolveModelHeaders(_model, signal) {
      headerSignal = signal;
      return new Promise<Record<string, string> | undefined>(() => undefined);
    },
  };

  assert.equal(await analyzeNativeDecision(registry, MODEL, INPUT, 20, silentLogger), null);
  assert.equal(headerSignal?.aborted, true);
});

test("caller abort promptly cancels pending header resolution", async () => {
  let headersStarted!: () => void;
  let headerSignal: AbortSignal | undefined;
  const started = new Promise<void>((resolve) => { headersStarted = resolve; });
  const registry: JudgmentModelRegistry = {
    resolver: () => "registry-key",
    resolveModelHeaders(_model, signal) {
      headerSignal = signal;
      headersStarted();
      return new Promise<Record<string, string> | undefined>(() => undefined);
    },
  };
  const controller = new AbortController();
  const pending = analyzeNativeDecision(registry, MODEL, INPUT, 5_000, silentLogger, controller.signal);

  await started;
  controller.abort();
  assert.equal(await pending, null);
  assert.equal(headerSignal?.aborted, true);
});
