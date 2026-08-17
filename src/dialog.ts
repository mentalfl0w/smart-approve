/**
 * Smart Approve — confirmation dialog.
 *
 * Shows the confirmation dialog (with optional remember choices) and
 * formats the LLM risk analysis into dialog body lines.
 */

import type { ExtensionCtx, RememberChoice, RiskAnalysis } from "./types";
import type { I18n } from "./i18n";

/** Format model analysis into dialog body lines. */
export function formatAnalysis(analysis: RiskAnalysis | null, t: I18n): string | null {
  if (!analysis) return null;
  const lines: string[] = [];
  if (analysis.risk) lines.push(`${t.risk}: ${analysis.risk}`);
  if (analysis.summary) lines.push(`${t.summary}: ${analysis.summary}`);
  if (analysis.detail) lines.push(`${t.detail}: ${analysis.detail}`);
  if (analysis.recommend) lines.push(`${t.recommend}: ${analysis.recommend}`);
  return lines.length ? lines.join("\n") : null;
}
/**
 * Confirmation dialog with optional remember option.
 *
 * scope "both" (default): three choices — session allow, permanent allow,
 * deny.  scope "session": two choices — session allow, deny (used by tools
 * where permanent remember is meaningless, e.g. eval code).
 *
 * If rememberDecisions is disabled or the host lacks ui.select, falls back
 * to a simple confirm() (allow / deny).
 *
 * Returns: { ok, remember } where ok=false means the user denied.
 */
export async function confirmWithRemember(
  ctx: ExtensionCtx,
  title: string,
  body: string,
  t: I18n,
  rememberDecisions: boolean,
  scope: "session" | "both" = "both",
): Promise<{ ok: boolean; remember: RememberChoice }> {
  // If remember is disabled or UI doesn't support select, use simple confirm
  if (!rememberDecisions || typeof ctx.ui.select !== "function") {
    const ok = await ctx.ui.confirm(title, body);
    return { ok, remember: "none" };
  }

  const denyLabel = "❌ " + (ctx.lang === "zh" ? "拒绝" : "Deny");
  const choices = scope === "both"
    ? [t.sessionAllow, t.permanentAllow, denyLabel]
    : [t.sessionAllow, denyLabel];
  const choice = await ctx.ui.select(title + "\n\n" + body, choices);

  // OMP resolves select() with the option label (string), not an index.
  // Accept both string-label and numeric-index for robustness across hosts.
  if (choice === t.sessionAllow || choice === 0) return { ok: true, remember: "session" };
  if (scope === "both" && (choice === t.permanentAllow || choice === 1)) {
    return { ok: true, remember: "permanent" };
  }
  if (scope === "session" && choice === 1) return { ok: false, remember: "none" };
  if (choice === denyLabel || choice === 2) return { ok: false, remember: "none" };
  // Undefined / null / anything else → treat as deny (fail-closed).
  return { ok: false, remember: "none" };
}
