import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getI18n } from "./i18n.ts";
import { HostResolver, ModelInvoker } from "./host.ts";
import { Logger } from "./logger.ts";
import type { ExtensionCtx, JudgmentModel } from "./types.ts";

const translations = getI18n("en");
const SUBJECT = "git push --force origin feature";
const BEHAVIORS = ["Force-push to a remote branch"];
const CONTEXT = "The user asked to publish the feature branch.";

const nativeModel: JudgmentModel = {
  id: "openai/gpt-6-luna-decisions",
  provider: "openrouter",
  api: "openrouter-decisions",
  kind: "judge",
};

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function createRpcExecutable(directory: string): { executable: string; modelLog: string } {
  const executable = path.join(directory, "fake-omp");
  const modelLog = path.join(directory, "models.log");
  const ready = JSON.stringify({ type: "ready", protocolVersion: 1 });
  const noTextResponse = JSON.stringify({ type: "agent_end", isTerminal: true, messages: [] });
  const response = JSON.stringify({
    type: "agent_end",
    isTerminal: true,
    messages: [{
      role: "assistant",
      content: [{ type: "text", text: JSON.stringify({ risk: "low", recommend: "allow" }) }],
    }],
  });

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
printf '%s\\n' "$model" >> ${shellQuote(modelLog)}
printf '%s\\n' ${shellQuote(ready)}
while IFS= read -r line; do
  if [ "$model" = "@tiny" ]; then
    printf '%s\\n' ${shellQuote(noTextResponse)}
  else
    printf '%s\\n' ${shellQuote(response)}
  fi
done
`, "utf8");
  fs.chmodSync(executable, 0o755);
  return { executable, modelLog };
}

function makeContext(model: JudgmentModel): ExtensionCtx {
  return {
    hasUI: true,
    ui: {
      confirm: async () => true,
      setStatus: () => undefined,
    },
    modelRegistry: {
      getAvailable(kind) {
        assert.equal(kind, "all");
        return [model];
      },
    },
  };
}

test("unavailable native judgment advances to chat fallbacks without sending the judge model to chat", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const logger = new Logger(path.join(directory, "logs"));
  const { executable, modelLog } = createRpcExecutable(directory);
  const host = new HostResolver(logger);
  host.resolve = () => executable;
  const invoker = new ModelInvoker(host, logger, 2_000, 0);
  const ctx = makeContext(nativeModel);

  try {
    for (const selector of [`${nativeModel.provider}/${nativeModel.id}`, nativeModel.id]) {
      const result = await invoker.analyze(
        SUBJECT,
        "Shell command",
        BEHAVIORS,
        CONTEXT,
        translations,
        selector,
        undefined,
        ctx,
      );
      assert.deepEqual(result, { risk: "low", recommend: "allow" });
    }
    assert.deepEqual(fs.readFileSync(modelLog, "utf8").trim().split("\n"), ["@tiny", "@smol", "@tiny", "@smol"]);
  } finally {
    invoker.dispose();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("caller abort prevents chat fallback after native selection", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  const logger = new Logger(path.join(directory, "logs"));
  const host = new HostResolver(logger);
  let hostResolved = false;
  host.resolve = () => {
    hostResolved = true;
    return null;
  };
  const invoker = new ModelInvoker(host, logger, 2_000, 0);

  try {
    const result = await invoker.analyze(
      SUBJECT,
      "Shell command",
      BEHAVIORS,
      CONTEXT,
      translations,
      `${nativeModel.provider}/${nativeModel.id}`,
      AbortSignal.abort(),
      makeContext(nativeModel),
    );
    assert.equal(result, null);
    assert.equal(hostResolved, false);
  } finally {
    invoker.dispose();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
