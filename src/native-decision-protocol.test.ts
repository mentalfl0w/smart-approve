import { test } from "node:test";
import assert from "node:assert/strict";
import { NativeDecisionProtocol } from "./native-decision-protocol.ts";

test("native decisions preserve high risk even when recommendation allows", () => {
  assert.deepEqual(new NativeDecisionProtocol().parse({
    answers: {
      risk: { type: "choice", choice: "high" },
      recommend: { type: "choice", choice: "allow" },
    },
  }), { risk: "high", recommend: "allow" });
});

test("native decisions reject wrong question types, missing answers, and unknown choices", () => {
  const protocol = new NativeDecisionProtocol();
  const validRecommendation = { type: "choice", choice: "allow" };

  assert.equal(protocol.parse({
    answers: {
      risk: { type: "score", choice: "high" },
      recommend: validRecommendation,
    },
  }), null);
  assert.equal(protocol.parse({
    answers: {
      risk: { type: "choice", choice: "critical" },
      recommend: validRecommendation,
    },
  }), null);
  assert.equal(protocol.parse({
    answers: {
      risk: { type: "choice", choice: "low" },
      recommend: { type: "choice", choice: "approve" },
    },
  }), null);
  assert.equal(protocol.parse({
    answers: { risk: { type: "choice", choice: "low" } },
  }), null);
});
