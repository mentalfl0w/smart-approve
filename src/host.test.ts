import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createNativeJudge, isJudgmentApi } from "@oh-my-pi/pi-ai";
import type { ApiKey, Model, NativeJudgeConnection } from "@oh-my-pi/pi-ai";
import { getBundledModel } from "@oh-my-pi/pi-catalog/models";
import { getI18n } from "./i18n.ts";
import { HostResolver, ModelInvoker } from "./host.ts";
import { Logger } from "./logger.ts";
import type { JudgmentModelRegistry, NativeJudgmentSupport } from "./types.ts";

const t = getI18n("en");
const silentLogger = { log(_message: string) {} } as Logger;

const openrouterJudgmentModel = {
  ...getBundledModel("openrouter", "~typesafe/jev-latest"),
  baseUrl: "https://judgment.example/api/alpha/",
  requestModelId: "wire/typesafe/jev-latest",
};

function makeHost(executable: string): HostResolver {
  const host = new HostResolver(silentLogger);
  host.resolve = () => executable;
  return host;
}

function makeForbiddenHost(): HostResolver {
  const host = new HostResolver(silentLogger);
  host.resolve = () => {
    throw new Error("Native judgment must not resolve a chat host");
  };
  return host;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function createRpcExecutable(dir: string, retryConfiguredModel?: string): { executable: string; modelsLog: string } {
  const executable = path.join(dir, "fake-omp");
  const modelsLog = path.join(dir, "rpc-models.log");
  const emptyFrame = JSON.stringify({ type: "agent_end", messages: [] });
  const result = JSON.stringify({ risk: "low", recommend: "allow" });
  const answerFrame = JSON.stringify({
    type: "agent_end",
    messages: [{ role: "assistant", content: [{ type: "text", text: result }] }],
  });
  const conditional = retryConfiguredModel
    ? `if [ "$model" = ${shellQuote(retryConfiguredModel)} ]; then\n    printf '%s\\n' ${shellQuote(emptyFrame)}\n  else\n    printf '%s\\n' ${shellQuote(answerFrame)}\n  fi`
    : `printf '%s\\n' ${shellQuote(answerFrame)}`;
  fs.writeFileSync(executable, `#!/bin/sh
model=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--model" ]; then
    shift
    model="$1"
    break
  fi
  shift
done
printf '%s\\n' "$model" >> ${shellQuote(modelsLog)}
printf '%s\\n' ${shellQuote(JSON.stringify({ type: "ready", protocolVersion: 1 }))}
while IFS= read -r line; do
  ${conditional}
done
`, "utf8");
  fs.chmodSync(executable, 0o755);
  return { executable, modelsLog };
}

interface CapturedNativeRequest {
  url: string;
  method: string | undefined;
  headers: Headers;
  body: { model?: string };
}

const nativeJudgmentResponse = {
  model: "fixed-native-response",
  answers: {
    risk: {
      type: "choice",
      choice: "low",
      probabilities: { low: 1, medium: 0, high: 0 },
      confidence: 1,
    },
    recommendation: {
      type: "choice",
      choice: "allow",
      probabilities: { allow: 1, deny: 0 },
      confidence: 1,
    },
  },
  usage: { input_tokens: 12, output_tokens: 3 },
};

function makeNativeSupport(fetch: NonNullable<NativeJudgeConnection["fetch"]>): NativeJudgmentSupport {
  return {
    isJudgmentApi,
    createNativeJudge(model, connection: NativeJudgeConnection) {
      return createNativeJudge(model, { ...connection, fetch });
    },
  };
}
 
function makeRegistry(
  model: Model,
  options: { find?: JudgmentModelRegistry["find"]; key?: ApiKey; authHeaders?: Record<string, string>; resolvedHeaders?: Record<string, string> } = {},
): JudgmentModelRegistry {
  return {
    find(provider, id) {
      if (options.find) return options.find(provider, id);
      return model;
    },
    async getApiKeyAndHeaders(_model) {
      const apiKey = options.key ?? "test-registry-token";
      const headers = options.authHeaders ?? { "x-auth-source": "registry-auth" };
      return { ok: true, apiKey, headers };
    },
    async resolveModelHeaders(_model) {
      const headers = options.resolvedHeaders ?? { "x-model-route": "catalog-header" };
      return headers;
    },
  };
}

const subject = "git push --force origin feature";
const behaviorLabels = ["Force-push to a remote branch"];
const contextSection = "Recent assistant context.";

test("OpenRouter native judgment uses bundled model transport metadata", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  let nativeRequest: CapturedNativeRequest | undefined;
  const nativeFetch: NonNullable<NativeJudgeConnection["fetch"]> = async (input, init) => {
    nativeRequest = {
      url: String(input),
      method: init?.method,
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body)) as CapturedNativeRequest["body"],
    };
    return Response.json(nativeJudgmentResponse);
  };
  const model = openrouterJudgmentModel;
  const registry = makeRegistry(model, {
    find(provider, id) {
      if (provider === model.provider && id === model.id) return model;
      return undefined;
    },
    key: async () => "registry-auth-token",
    authHeaders: { "x-auth-source": "credential-registry" },
    resolvedHeaders: { "x-model-route": "resolved-model-header" },
  });
  const invoker = new ModelInvoker(makeForbiddenHost(), silentLogger, 2_000, 0, makeNativeSupport(nativeFetch));
  try {
    const selector = `${model.provider}/${model.id}`;
    const result = await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, selector, undefined, registry);
    assert.equal(result?.risk, "low");
    assert.equal(result?.recommend, "allow");
    assert.ok(nativeRequest);
    assert.equal(nativeRequest.url, "https://judgment.example/api/alpha/decisions");
    assert.equal(nativeRequest.method, "POST");
    assert.equal(nativeRequest.body.model, "wire/typesafe/jev-latest");
    assert.equal(nativeRequest.headers.get("authorization"), "Bearer registry-auth-token");
    assert.equal(nativeRequest.headers.get("x-auth-source"), "credential-registry");
    assert.equal(nativeRequest.headers.get("x-model-route"), "resolved-model-header");
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("registered chat models, aliases, and bare ids keep using the RPC fallback chain", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const chatModel = getBundledModel("openrouter", "openai/gpt-4o");
  const chatSelector = `${chatModel.provider}/${chatModel.id}`;
  const { executable, modelsLog } = createRpcExecutable(dir, chatSelector);
  const registry = makeRegistry(chatModel, {
    find(provider, id) {
      if (provider === chatModel.provider && id === chatModel.id) return chatModel;
      return undefined;
    },
  });
  const invoker = new ModelInvoker(makeHost(executable), silentLogger, 2_000, 0, makeNativeSupport(fetch));
  try {
    const chatResult = await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, chatSelector, undefined, registry);
    assert.equal(chatResult?.recommend, "allow");
    const aliasResult = await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, "@smol", undefined, registry);
    const bareIdResult = await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, "bare-model-id", undefined, registry);
    assert.equal(aliasResult?.recommend, "allow");
    assert.equal(bareIdResult?.recommend, "allow");
    assert.deepEqual(fs.readFileSync(modelsLog, "utf8").trim().split("\n"), [
      chatSelector,
      chatSelector,
      "@tiny",
      "@smol",
      "bare-model-id",
    ]);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("generic Pi invocation keeps qualified model selectors on RPC without a registry", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const { executable, modelsLog } = createRpcExecutable(dir);
  const invoker = new ModelInvoker(makeHost(executable), silentLogger, 2_000, 0);
  try {
    const result = await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, "native-provider/model/id");
    assert.equal(result?.risk, "low");
    assert.deepEqual(fs.readFileSync(modelsLog, "utf8").trim().split("\n"), ["native-provider/model/id"]);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("catalog lookup errors return no verdict without falling back to RPC", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const { executable, modelsLog } = createRpcExecutable(dir);
  const model = openrouterJudgmentModel;
  const registry = makeRegistry(model, {
    find() {
      throw new Error("catalog unavailable");
    },
  });
  const invoker = new ModelInvoker(makeHost(executable), silentLogger, 2_000, 0, makeNativeSupport(fetch));
  try {
    const selector = `${model.provider}/${model.id}`;
    assert.equal(await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, selector, undefined, registry), null);
    assert.equal(fs.existsSync(modelsLog), false);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("native API errors return no verdict and never enter chat RPC", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const { executable, modelsLog } = createRpcExecutable(dir);
  let requestUrl: string | undefined;
  const failingFetch: NonNullable<NativeJudgeConnection["fetch"]> = async input => {
    requestUrl = String(input);
    return new Response("invalid judgment request", { status: 400 });
  };
  const model = openrouterJudgmentModel;
  const registry = makeRegistry(model);
  const invoker = new ModelInvoker(makeHost(executable), silentLogger, 2_000, 0, makeNativeSupport(failingFetch));
  try {
    const selector = `${model.provider}/${model.id}`;
    assert.equal(await invoker.analyze(subject, "Shell command", behaviorLabels, contextSection, t, selector, undefined, registry), null);
    assert.equal(requestUrl, "https://judgment.example/api/alpha/decisions");
    assert.equal(fs.existsSync(modelsLog), false);
  } finally {
    invoker.dispose();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
