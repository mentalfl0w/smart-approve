/**
 * Smart Approve — auto-mode decision policy.
 *
 * Turns a parsed LLM risk analysis into a verdict when mode is "auto".
 * The policy has no fallback verdict: when the model produced no usable
 * answer, `decide()` returns null and the approval flow asks the user
 * (interactive UI) or blocks (no UI).  Operations flagged as requiring a
 * user decision never reach this policy's verdict; they always ask.
 *
 * Kept as a pure class so the matrix is unit-testable without spawning omp.
 */

import type { RiskAnalysis } from "./types";
import type { SmartApproveConfig } from "./config";

/** One resolved verdict for the auto-mode path. */
export interface PolicyDecision {
  verdict: "allow" | "block";
  /** Stable machine id for logging; not user-facing. */
  reason: "ai-risk" | "ai-recommend";
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
 *  - no usable verdict       -> null (the flow asks the user or blocks)
 */
export class AutoDecisionPolicy {
  constructor(private readonly config: SmartApproveConfig) {}

  /** Decide from a model analysis.  null means "no usable verdict". */
  decide(analysis: RiskAnalysis | null): PolicyDecision | null {
    const recommend = normalizeRecommend(analysis?.recommend);
    const risk = normalizeRisk(analysis?.risk);

    if (recommend === "deny") return { verdict: "block", reason: "ai-recommend" };

    if (risk === "high") return { verdict: "block", reason: "ai-risk" };
    if (risk === "medium" && this.config.autoBlockRisk === "medium") {
      return { verdict: "block", reason: "ai-risk" };
    }

    // Any parseable verdict (recommend=allow, or risk=low/medium below the
    // threshold) permits execution.  Not enough information -> no verdict.
    if (recommend === "allow" || risk !== null) return { verdict: "allow", reason: "ai-risk" };

    return null;
  }
}
