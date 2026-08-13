import { test } from "node:test";
import assert from "node:assert/strict";
import {
  enqueueSerialized,
  extractAssistantText,
  shouldClearProcRef,
  shouldRetryFresh,
  shouldSettleAgentEnd,
} from "./analysis-policy.ts";

test("enqueueSerialized runs the next prompt after a rejected spawn", async () => {
  const poisoned = Promise.reject(new Error("rpc process exited before ready"));
  poisoned.catch(() => undefined);
  const text = await enqueueSerialized(poisoned, async () => "ok");
  assert.equal(text, "ok");
});

test("enqueueSerialized still propagates a failure of the new run", async () => {
  const ok = Promise.resolve();
  await assert.rejects(
    enqueueSerialized(ok, async () => { throw new Error("spawn failed"); }),
    /spawn failed/,
  );
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

test("extractAssistantText prefers the last assistant message", () => {
  const messages = [
    { role: "user", content: [{ type: "text", text: "hi" }] },
    { role: "assistant", content: [{ type: "text", text: "the answer" }] },
  ];
  assert.equal(extractAssistantText(messages, "stale delta"), "the answer");
});

test("extractAssistantText falls back to deltas when messages carry no text", () => {
  assert.equal(extractAssistantText([], "streamed delta"), "streamed delta");
  assert.equal(extractAssistantText([{ role: "user", content: [] }], "delta"), "delta");
});

test("extractAssistantText returns empty when nothing has text", () => {
  assert.equal(extractAssistantText([], ""), "");
  assert.equal(extractAssistantText([{ role: "user", content: [] }], "  "), "");
});

test("shouldRetryFresh only when empty and not aborted", () => {
  assert.equal(shouldRetryFresh(null, false), true);
  assert.equal(shouldRetryFresh("", false), true);
  assert.equal(shouldRetryFresh("ok", false), false);
  assert.equal(shouldRetryFresh(null, true), false);
});
