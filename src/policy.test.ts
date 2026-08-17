import { test } from "node:test";
import assert from "node:assert/strict";
import { AutoDecisionPolicy } from "./policy.ts";
import type { SmartApproveConfig } from "./config.ts";

function makeConfig(overrides: Partial<SmartApproveConfig> = {}): SmartApproveConfig {
  return {
    enabled: true,
    mode: "auto",
    autoBlockRisk: "high",
    autoFallback: "regex",
    autoInHeadless: false,
    coverage: { eval: true },
    protectedPaths: [],
    llmAnalysis: true,
    rememberDecisions: true,
    contextMaxChars: 3000,
    analysisTimeoutMs: 30_000,
    rpcIdleTimeoutMs: 600_000,
    model: "@tiny",
    ...overrides,
  };
}

test("recommend deny blocks regardless of risk", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  const d = p.decide({ risk: "low", recommend: "deny" }, false);
  assert.equal(d.verdict, "block");
  assert.equal(d.reason, "ai-recommend");
});

test("risk high blocks even when recommend says allow (conflict resolves stricter)", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(p.decide({ risk: "high", recommend: "allow" }, false).verdict, "block");
  assert.equal(p.decide({ risk: "high" }, false).verdict, "block");
});

test("risk medium blocks only when autoBlockRisk is medium", () => {
  assert.equal(
    new AutoDecisionPolicy(makeConfig()).decide({ risk: "medium" }, false).verdict,
    "allow",
  );
  assert.equal(
    new AutoDecisionPolicy(makeConfig({ autoBlockRisk: "medium" }))
      .decide({ risk: "medium" }, false).verdict,
    "block",
  );
});

test("low risk or explicit allow passes", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(p.decide({ risk: "low" }, false).verdict, "allow");
  assert.equal(p.decide({ risk: "low", recommend: "allow" }, false).verdict, "allow");
});

test("recommend values are normalized (yes/no variants)", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(p.decide({ recommend: "yes" }, false).verdict, "allow");
  assert.equal(p.decide({ recommend: "NO" }, false).verdict, "block");
});

test("no analysis: fallback regex allows without deny tier", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  const d = p.decide(null, false);
  assert.equal(d.verdict, "allow");
  assert.equal(d.reason, "fallback-regex");
});

test("no analysis: fallback regex blocks deny-tier behavior", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  const d = p.decide(null, true);
  assert.equal(d.verdict, "block");
  assert.equal(d.reason, "fallback-deny-tier");
});

test("no analysis: fallback block always blocks", () => {
  const p = new AutoDecisionPolicy(makeConfig({ autoFallback: "block" }));
  assert.equal(p.decide(null, false).verdict, "block");
  assert.equal(p.decide(null, false).reason, "fallback-block");
});

test("unreadable analysis falls back (garbage fields)", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(p.decide({ risk: "banana", recommend: "maybe" }, false).reason, "fallback-regex");
  assert.equal(p.decide({ summary: "text only" }, true).reason, "fallback-deny-tier");
});
