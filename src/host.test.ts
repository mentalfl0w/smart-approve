import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getBundledModel } from "@oh-my-pi/pi-catalog/models";
import { getI18n } from "./i18n.ts";
import { HostResolver, ModelInvoker } from "./host.ts";
import { Logger } from "./logger.ts";
import type { ExtensionCtx, HostModelRegistry } from "./types.ts";
import type { OmpNativeJudgmentSupport } from "./omp-native-judge-adapter.ts";

const translations = getI18n("en");
const subject = "git push --force origin feature";
const behaviorLabels = ["Force-push to a remote branch"];
const contextSection = "The user asked to publish the feature branch.";

function contextWithRegistry(modelRegistry: HostModelRegistry): ExtensionCtx {
  return {
    hasUI: true,
    modelRegistry,
    ui: {
      confirm: async () => true,
      setStatus: () => undefined,
    },
  };
}

function makeForbiddenRpcHost(logger: Logger): HostResolver {
  const host = new HostResolver(logger);
  host.resolve = () => {
    throw new Error("A registered native decision model must not use chat RPC");
  };
  return host;
}

test("ModelInvoker routes Pi classifier models through ctx.modelRegistry.classify", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-pi-classifier-"));
  const logger = new Logger(dir);
  const classifierModel = { id: "jev-latest", provider: "typesafe", type: "classifier" };
  const registry: HostModelRegistry = {
    getModelOfType: () => classifierModel,
    classify: async () => ({
      stopReason: "stop",
      answers: {
        risk: { type: "choice", choice: "low", probabilities: {}, confidence: 1 },
        recommend: { type: "choice", choice: "allow", probabilities: {}, confidence: 1 },
      },
    }),
  };
  const invoker = new ModelInvoker(makeForbiddenRpcHost(logger), logger, 1_000, 0);

  try {
    const result = await invoker.analyze(
      subject,
      "Shell command",
      behaviorLabels,
      contextSection,
      translations,
      "typesafe/jev-latest",
      undefined,
      contextWithRegistry(registry),
    );
    assert.deepEqual(result, { risk: "low", recommend: "allow" });
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("ModelInvoker routes OMP judgment models through the OMP native factory", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-omp-judge-"));
  const logger = new Logger(dir);
  const model = getBundledModel("openrouter", "~typesafe/jev-latest");
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => ({ "x-model-route": "catalog" }),
  };
  const support: OmpNativeJudgmentSupport = {
    isJudgmentApi: (api) => api === model.api,
    createNativeJudge: () => ({
      judge: async () => ({
        answers: {
          risk: { type: "choice", choice: "high" },
          recommend: { type: "choice", choice: "allow" },
        },
      }),
    }),
  };
  const invoker = new ModelInvoker(makeForbiddenRpcHost(logger), logger, 1_000, 0, async () => support);

  try {
    const result = await invoker.analyze(
      subject,
      "Shell command",
      behaviorLabels,
      contextSection,
      translations,
      `${model.provider}/${model.id}`,
      undefined,
      contextWithRegistry(registry),
    );
    assert.deepEqual(result, { risk: "high", recommend: "allow" });
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("recognized native OMP failures return no verdict instead of falling back to chat", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-omp-auth-failure-"));
  const logger = new Logger(dir);
  const model = getBundledModel("openrouter", "~typesafe/jev-latest");
  const registry: HostModelRegistry = {
    find: () => model,
    resolver: () => {
      throw new Error("credential unavailable");
    },
    resolveModelHeaders: async () => undefined,
  };
  const support: OmpNativeJudgmentSupport = {
    isJudgmentApi: () => true,
  };
  const invoker = new ModelInvoker(makeForbiddenRpcHost(logger), logger, 1_000, 0, async () => support);

  try {
    const result = await invoker.analyze(
      subject,
      "Shell command",
      behaviorLabels,
      contextSection,
      translations,
      `${model.provider}/${model.id}`,
      undefined,
      contextWithRegistry(registry),
    );
    assert.equal(result, null);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test("registered OMP chat models keep the chat RPC path", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-omp-chat-"));
  const logger = new Logger(dir);
  let rpcResolved = false;
  const host = new HostResolver(logger);
  host.resolve = () => {
    rpcResolved = true;
    return null;
  };
  const chatModel = {
    ...getBundledModel("openrouter", "~typesafe/jev-latest"),
    id: "gpt-5.5",
    provider: "openai-codex",
    api: "openai-codex-responses",
    kind: "chat" as const,
  };
  const registry: HostModelRegistry = {
    find: () => chatModel,
    resolver: () => "registry-token",
    resolveModelHeaders: async () => undefined,
  };
  const invoker = new ModelInvoker(host, logger, 1_000, 0, async () => ({
    isJudgmentApi: () => false,
    createNativeJudge: () => {
      throw new Error("chat models must not use the native judge factory");
    },
  }));

  try {
    const result = await invoker.analyze(
      subject,
      "Shell command",
      behaviorLabels,
      contextSection,
      translations,
      "openai-codex/gpt-5.5",
      undefined,
      contextWithRegistry(registry),
    );
    assert.equal(result, null);
    assert.equal(rpcResolved, true);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("unregistered model specs retain the existing chat RPC fallback path", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-rpc-fallback-"));
  const logger = new Logger(dir);
  let rpcResolved = false;
  const host = new HostResolver(logger);
  host.resolve = () => {
    rpcResolved = true;
    return null;
  };
  const registry: HostModelRegistry = {
    getModelOfType: () => undefined,
    find: () => undefined,
  };
  const invoker = new ModelInvoker(host, logger, 1_000, 0);

  try {
    const result = await invoker.analyze(
      subject,
      "Shell command",
      behaviorLabels,
      contextSection,
      translations,
      "openrouter/regular-chat-model",
      undefined,
      contextWithRegistry(registry),
    );
    assert.equal(result, null);
    assert.equal(rpcResolved, true);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
