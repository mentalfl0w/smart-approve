/**
 * Smart Approve — auto-mode decision policy.
 *
 * Turns a parsed LLM risk analysis into a verdict when mode is "auto".
 * When the LLM chain fails entirely (or the analysis is unreadable), the
 * verdict comes from the configured fallback: hard block, or the regex
 * deny tier.  Kept as a pure class so the matrix is unit-testable without
 * spawning omp.
 */

import type { RiskAnalysis } from "./types";
import type { SmartApproveConfig } from "./config";

/** One resolved verdict for the auto-mode path. */
export interface PolicyDecision {
  verdict: "allow" | "block";
  /** Stable machine id for logging; not user-facing. */
  reason: "ai-risk" | "ai-recommend" | "fallback-block" | "fallback-deny-tier" | "fallback-regex";
}

function normalizeRisk(raw: string | undefined): "low" | "medium" | "high" | null {
  if (typeof raw !== "string") return null;
  const v = raw.trim().toLowerCase();
  return v === "low" || v === "medium" || v === "high" ? v : null;
}

function normalizeRecommend(raw: string | undefined): "allow" | "deny" | null {
  if (typeof raw !== "string") return null;
  const v = raw.trim().toLowerCase();
  if (v === "allow" || v === "approve" || v === "yes") return "allow";
  if (v === "deny" || v === "block" || v === "reject" || v === "no") return "deny";
  return null;
}

/**
 * Auto-mode decision policy.
 *
 * Rules:
 *  - recommend = deny        -> block (explicit model veto)
 *  - risk >= autoBlockRisk   -> block ("high" always blocks; "medium" also
 *    blocks when autoBlockRisk is "medium")
 *  - risk = high but recommend = allow -> block (contradiction resolves to
 *    the stricter signal; the command text is untrusted input)
 *  - no usable verdict       -> fallback: autoFallback "block", else the
 *    deny tier (regex-confident behaviors), else allow.
 */
export class AutoDecisionPolicy {
  constructor(private readonly config: SmartApproveConfig) {}

  /** Decide from an LLM analysis plus the regex deny-tier signal. */
  decide(analysis: RiskAnalysis | null, denyTierHit: boolean): PolicyDecision {
    const recommend = normalizeRecommend(analysis?.recommend);
    const risk = normalizeRisk(analysis?.risk);

    if (recommend === "deny") return { verdict: "block", reason: "ai-recommend" };

    if (risk === "high") return { verdict: "block", reason: "ai-risk" };
    if (risk === "medium" && this.config.autoBlockRisk === "medium") {
      return { verdict: "block", reason: "ai-risk" };
    }

    // Any parseable verdict (recommend=allow, or risk=low/medium below the
    // threshold) permits execution.  No verdict at all -> fallback.
    if (recommend === "allow" || risk !== null) return { verdict: "allow", reason: "ai-risk" };

    return this.fallback(denyTierHit);
  }

  private fallback(denyTierHit: boolean): PolicyDecision {
    if (this.config.autoFallback === "block") {
      return { verdict: "block", reason: "fallback-block" };
    }
    if (denyTierHit) return { verdict: "block", reason: "fallback-deny-tier" };
    return { verdict: "allow", reason: "fallback-regex" };
  }
}
