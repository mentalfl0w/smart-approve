import { test } from "node:test";
import assert from "node:assert/strict";
import { vi } from "bun:test";
import { getBundledModel } from "@oh-my-pi/pi-catalog/models";
import type {
  ApiKey,
  Judge,
  JudgeOptions,
  JudgmentRequest,
  JudgmentResult,
  Model,
  Questions,
} from "@oh-my-pi/pi-ai";
import { analyzeNativeDecision } from "./native-decisions.ts";
import type { JudgmentModelRegistry, NativeJudgmentSupport } from "./types.ts";
import type { LoggerLike } from "./logger.ts";

type CredentialResolution = {
  ok: true;
  apiKey?: ApiKey;
  headers?: Record<string, string>;
} | {
  ok: false;
  error: string;
};
type JudgeRun = (request: unknown, signal: AbortSignal | undefined) => Promise<unknown>;
type CredentialLookup = () => Promise<CredentialResolution>;
type HeaderLookup = (signal?: AbortSignal) => Promise<Record<string, string> | undefined>;

interface FixtureOptions {
  credentials?: CredentialLookup;
  headers?: HeaderLookup;
  judge?: JudgeRun;
}

interface NativeDecisionFixture {
  model: Model;
  registry: JudgmentModelRegistry;
  support: NativeJudgmentSupport;
  logger: LoggerLike;
  judgeCreated: boolean;
  judgeSignal: AbortSignal | undefined;
}

const MODEL: Model = getBundledModel("openrouter", "~typesafe/jev-latest");

const INPUT = {
  subject: "printf 'hello' > ./output.txt",
  subjectLabel: "Command",
  behaviorLabels: ["writes files", "detected shell command"],
  contextSection: "Original task: save the generated greeting to output.txt.",
};

const VALID_ANSWERS = {
  risk: {
    type: "choice",
    choice: "medium",
    probabilities: { low: 0.1, medium: 0.8, high: 0.1 },
    confidence: 0.8,
  },
  recommendation: {
    type: "choice",
    choice: "allow",
    probabilities: { allow: 0.75, deny: 0.25 },
    confidence: 0.75,
  },
} as const;

const NEVER_RESOLVES = <T>(): Promise<T> => new Promise<T>(() => undefined);

function makeFixture(options: FixtureOptions = {}): NativeDecisionFixture {
  let judgeCreated = false;
  let judgeSignal: AbortSignal | undefined;

  const registry: JudgmentModelRegistry = {
    find: () => MODEL,
    getApiKeyAndHeaders: async () => options.credentials
      ? options.credentials()
      : { ok: true, apiKey: "test-secret", headers: { "x-provider": "provider" } },
    resolveModelHeaders: async (_model, signal) => options.headers
      ? options.headers(signal)
      : { "x-model": "model" },
  };

  const support: NativeJudgmentSupport = {
    isJudgmentApi: (api) => api === MODEL.api,
    createNativeJudge: (): Judge => {
      judgeCreated = true;
      return {
        label: "native-test",
        judge<Q extends Questions>(_request: JudgmentRequest<Q>, judgeOptions?: JudgeOptions): Promise<JudgmentResult<Q>> {
          judgeSignal = judgeOptions?.signal;
          const run = options.judge ?? (async () => ({ answers: VALID_ANSWERS }));
          // Deliberately malformed fixture values exercise the adapter's untrusted-output schema.
          return run(_request, judgeOptions?.signal).then((value) => value as unknown as JudgmentResult<Q>);
        },
      };
    },
  };
  const logger: LoggerLike = { log: () => undefined };

  return {
    model: MODEL,
    registry,
    support,
    logger,
    get judgeCreated() { return judgeCreated; },
    get judgeSignal() { return judgeSignal; },
  };
}



function analyze(
  fixture: NativeDecisionFixture,
  timeoutMs = 1_000,
  signal?: AbortSignal,
) {
  return analyzeNativeDecision(
    fixture.support,
    fixture.registry,
    fixture.model,
    INPUT,
    timeoutMs,
    fixture.logger,
    signal,
  );
}

test("maps a valid medium/allow answer", async () => {
  const fixture = makeFixture();
  assert.deepEqual(await analyze(fixture), { risk: "medium", recommend: "allow" });
});

test("preserves ordinary low/allow and high/deny decisions", async () => {
  const lowAllow = makeFixture({
    judge: async () => ({ answers: {
      risk: { type: "choice", choice: "low", probabilities: { low: 0.8, medium: 0.1, high: 0.1 }, confidence: 0.8 },
      recommendation: VALID_ANSWERS.recommendation,
    } }),
  });
  assert.deepEqual(await analyze(lowAllow), { risk: "low", recommend: "allow" });

  const highDeny = makeFixture({
    judge: async () => ({ answers: {
      risk: { type: "choice", choice: "high", probabilities: { low: 0.1, medium: 0.2, high: 0.7 }, confidence: 0.7 },
      recommendation: { type: "choice", choice: "deny", probabilities: { allow: 0.1, deny: 0.9 }, confidence: 0.9 },
    } }),
  });
  assert.deepEqual(await analyze(highDeny), { risk: "high", recommend: "deny" });
});


const INVALID_ANSWERS: Array<{ name: string; value: unknown }> = [
  {
    name: "missing a risk label",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.2, medium: 0.8 } } },
  },
  {
    name: "an unexpected probability label",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.1, medium: 0.8, high: 0.1, other: 0 } } },
  },
  {
    name: "probabilities that do not sum approximately to one",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.1, medium: 0.7, high: 0.1 } } },
  },
  {
    name: "a negative probability",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: -0.1, medium: 0.8, high: 0.3 } } },
  },
  {
    name: "a probability above one",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.1, medium: 1.2, high: 0.1 } } },
  },
  {
    name: "a NaN probability",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.1, medium: Number.NaN, high: 0.1 } } },
  },
  {
    name: "an infinite probability",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, probabilities: { low: 0.1, medium: Number.POSITIVE_INFINITY, high: 0.1 } } },
  },
  {
    name: "a negative confidence",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, confidence: -0.01 } },
  },
  {
    name: "a confidence above one",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, confidence: 1.01 } },
  },
  {
    name: "a NaN confidence",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, confidence: Number.NaN } },
  },
  {
    name: "an infinite confidence",
    value: { ...VALID_ANSWERS, recommendation: { ...VALID_ANSWERS.recommendation, confidence: Number.POSITIVE_INFINITY } },
  },
  {
    name: "a choice that is not a probability maximum",
    value: { ...VALID_ANSWERS, risk: { ...VALID_ANSWERS.risk, choice: "low" } },
  },
  {
    name: "a refusal-shaped answer",
    value: { ...VALID_ANSWERS, risk: { type: "refusal", reason: "cannot answer" } },
  },
  {
    name: "a choice outside the expected labels",
    value: { ...VALID_ANSWERS, recommendation: { ...VALID_ANSWERS.recommendation, choice: "approve" } },
  },
  {
    name: "a missing confidence value",
    value: { ...VALID_ANSWERS, risk: { type: "choice", choice: "medium", probabilities: { low: 0.1, medium: 0.8, high: 0.1 } } },
  },
  {
    name: "a missing recommendation answer",
    value: { risk: VALID_ANSWERS.risk },
  },
  {
    name: "high risk paired with allow",
    value: {
      risk: { type: "choice", choice: "high", probabilities: { low: 0.1, medium: 0.2, high: 0.7 }, confidence: 0.7 },
      recommendation: VALID_ANSWERS.recommendation,
    },
  },
];

for (const { name, value } of INVALID_ANSWERS) {
  test(`returns no verdict for ${name}`, async () => {
    const fixture = makeFixture({ judge: async () => ({ answers: value }) });
    assert.equal(await analyze(fixture), null);
  });
}

test("returns no verdict for malformed judgment envelopes and native provider errors", async () => {
  const malformedEnvelope = makeFixture({ judge: async () => ({ answers: null }) });
  assert.equal(await analyze(malformedEnvelope), null);

  const providerError = makeFixture({ judge: async () => { throw new Error("provider failure"); } });
  assert.equal(await analyze(providerError), null);
});

test("returns no verdict without credentials and never constructs a judge", async () => {
  const fixture = makeFixture({ credentials: async () => ({ ok: false, error: "missing" }) });
  assert.equal(await analyze(fixture), null);
  assert.equal(fixture.judgeCreated, false);
});

test("returns no verdict when credentials have no API key", async () => {
  const absent = makeFixture({ credentials: async () => ({ ok: true, headers: undefined }) });
  assert.equal(await analyze(absent), null);
  assert.equal(absent.judgeCreated, false);

  const empty = makeFixture({ credentials: async () => ({ ok: true, apiKey: "", headers: undefined }) });
  assert.equal(await analyze(empty), null);
  assert.equal(empty.judgeCreated, false);
});

test("returns no verdict when credential lookup fails", async () => {
  const fixture = makeFixture({ credentials: async () => { throw new Error("registry failure"); } });
  assert.equal(await analyze(fixture), null);
  assert.equal(fixture.judgeCreated, false);
});

test("one deadline covers credential, header, and native judge operations", async () => {
  vi.useFakeTimers();
  try {
    const credentialWait = makeFixture({ credentials: () => NEVER_RESOLVES() });
    const credentialPending = analyze(credentialWait, 20);
    vi.advanceTimersByTime(20);
    assert.equal(await credentialPending, null);
    assert.equal(credentialWait.judgeCreated, false);

    let headerStarted!: () => void;
    const headerReady = new Promise<void>((resolve) => { headerStarted = resolve; });
    const headerWait = makeFixture({ headers: () => {
      headerStarted();
      return NEVER_RESOLVES();
    } });
    const headerPending = analyze(headerWait, 20);
    await headerReady;
    vi.advanceTimersByTime(20);
    assert.equal(await headerPending, null);
    assert.equal(headerWait.judgeCreated, false);

    let judgeStarted!: () => void;
    const judgeReady = new Promise<void>((resolve) => { judgeStarted = resolve; });
    const judgeWait = makeFixture({ judge: () => {
      judgeStarted();
      return NEVER_RESOLVES();
    } });
    const judgePending = analyze(judgeWait, 20);
    await judgeReady;
    vi.advanceTimersByTime(20);
    assert.equal(await judgePending, null);
    assert.equal(judgeWait.judgeSignal?.aborted, true);
  } finally {
    vi.useRealTimers();
  }
});
test("zero timeout disables the plugin deadline", async () => {
  vi.useFakeTimers();
  try {
    let started!: () => void;
    let resolveHeaders!: (headers: Record<string, string> | undefined) => void;
    let headerSignal: AbortSignal | undefined;
    const headerStarted = new Promise<void>((resolve) => { started = resolve; });
    const deferredHeaders = new Promise<Record<string, string> | undefined>((resolve) => { resolveHeaders = resolve; });
    const fixture = makeFixture({ headers: (signal) => {
      headerSignal = signal;
      started();
      return deferredHeaders;
    } });
    const pending = analyze(fixture, 0);
    await headerStarted;
    vi.advanceTimersByTime(60_000);
    let settled = false;
    void pending.then(() => { settled = true; });
    await Promise.resolve();
    assert.equal(settled, false);
    assert.equal(headerSignal?.aborted, false);
    resolveHeaders(undefined);
    assert.deepEqual(await pending, { risk: "medium", recommend: "allow" });
  } finally {
    vi.useRealTimers();
  }
});

test("external cancellation during credential lookup settles promptly without a verdict", async () => {
  let started!: () => void;
  const lookupStarted = new Promise<void>((resolve) => { started = resolve; });
  const fixture = makeFixture({ credentials: () => {
    started();
    return NEVER_RESOLVES();
  } });
  const controller = new AbortController();
  const pending = analyze(fixture, 0, controller.signal);
  await lookupStarted;
  controller.abort();
  assert.equal(await pending, null);
  assert.equal(fixture.judgeCreated, false);
});
test("external cancellation during model-header lookup settles promptly without a verdict", async () => {
  let started!: () => void;
  let headerSignal: AbortSignal | undefined;
  const headerStarted = new Promise<void>((resolve) => { started = resolve; });
  const fixture = makeFixture({ headers: (signal) => {
    headerSignal = signal;
    started();
    return NEVER_RESOLVES();
  } });
  const controller = new AbortController();
  const pending = analyze(fixture, 0, controller.signal);
  await headerStarted;
  controller.abort();
  assert.equal(await pending, null);
  assert.equal(headerSignal?.aborted, true);
  assert.equal(fixture.judgeCreated, false);
});

test("external cancellation aborts the native request and cannot fabricate a verdict", async () => {
  let started!: () => void;
  const judgeStarted = new Promise<void>((resolve) => { started = resolve; });
  const fixture = makeFixture({ judge: (_request, signal) => {
    assert.ok(signal);
    started();
    return NEVER_RESOLVES();
  } });
  const controller = new AbortController();
  const pending = analyze(fixture, 0, controller.signal);
  await judgeStarted;
  controller.abort();
  assert.equal(await pending, null);
  assert.equal(fixture.judgeSignal?.aborted, true);
});
