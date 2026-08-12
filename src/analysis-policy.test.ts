import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analysisModelChain,
  enqueueSerialized,
  shouldClearProcRef,
  shouldReuseRpcChild,
  shouldSettleAgentEnd,
} from "./analysis-policy.ts";

test("analysisModelChain does not append unresolved role aliases", () => {
  assert.deepEqual(analysisModelChain("acme/model-1"), ["acme/model-1"]);
  assert.deepEqual(analysisModelChain("@tiny"), ["@tiny"]);
});

test("enqueueSerialized runs the next prompt after a rejected spawn", async () => {
  const poisoned = Promise.reject(new Error("rpc process exited before ready"));
  poisoned.catch(() => undefined);
  const text = await enqueueSerialized(poisoned, async () => "ok");
  assert.equal(text, "ok");
});

test("shouldReuseRpcChild is false so each analysis gets a fresh child", () => {
  assert.equal(shouldReuseRpcChild("acme/model-1", "acme/model-1", true), false);
});

test("shouldClearProcRef only clears when the exiting child is current", () => {
  const current = { pid: 2 };
  const stale = { pid: 1 };
  assert.equal(shouldClearProcRef(current, stale), false);
  assert.equal(shouldClearProcRef(current, current), true);
  assert.equal(shouldClearProcRef(null, stale), false);
});

test("shouldSettleAgentEnd ignores non-terminal agent_end", () => {
  assert.equal(shouldSettleAgentEnd({ isTerminal: false }), false);
  assert.equal(shouldSettleAgentEnd({ isTerminal: true }), true);
  assert.equal(shouldSettleAgentEnd({}), true);
});
