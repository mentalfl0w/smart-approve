import { test } from "node:test";
import assert from "node:assert/strict";
import { AutoDecisionPolicy } from "./policy.ts";
import type { PolicyDecision } from "./policy.ts";
import type { RiskAnalysis } from "./types.ts";
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

function decided(policy: AutoDecisionPolicy, analysis: RiskAnalysis | null): PolicyDecision {
  const decision = policy.decide(analysis);
  assert.ok(decision, "expected a usable verdict");
  return decision;
}

test("recommend deny blocks regardless of risk", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  const d = decided(p, { risk: "low", recommend: "deny" });
  assert.equal(d.verdict, "block");
  assert.equal(d.reason, "ai-recommend");
});

test("risk high blocks even when recommend says allow (conflict resolves stricter)", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(decided(p, { risk: "high", recommend: "allow" }).verdict, "block");
  assert.equal(decided(p, { risk: "high" }).verdict, "block");
});

test("risk medium blocks only when autoBlockRisk is medium", () => {
  assert.equal(decided(new AutoDecisionPolicy(makeConfig()), { risk: "medium" }).verdict, "allow");
  assert.equal(
    decided(new AutoDecisionPolicy(makeConfig({ autoBlockRisk: "medium" })), {
      risk: "medium",
    }).verdict,
    "block",
  );
});

test("low risk or explicit allow passes", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(decided(p, { risk: "low" }).verdict, "allow");
  assert.equal(decided(p, { risk: "low", recommend: "allow" }).verdict, "allow");
});

test("recommend values are normalized (yes/no variants)", () => {
  const p = new AutoDecisionPolicy(makeConfig());
  assert.equal(decided(p, { recommend: "yes" }).verdict, "allow");
  assert.equal(decided(p, { recommend: "NO" }).verdict, "block");
});

test("missing or unreadable analysis returns no verdict (no regex fallback)", () => {
  const regexFallback = new AutoDecisionPolicy(makeConfig());
  assert.equal(regexFallback.decide(null), null);
  assert.equal(regexFallback.decide({ risk: "banana", recommend: "maybe" }), null);
  assert.equal(regexFallback.decide({ summary: "text only" }), null);

  // The legacy autoFallback setting must not turn no-verdict into allow.
  const blockFallback = new AutoDecisionPolicy(makeConfig({ autoFallback: "block" }));
  assert.equal(blockFallback.decide(null), null);
  assert.equal(blockFallback.decide({ summary: "text only" }), null);
});
