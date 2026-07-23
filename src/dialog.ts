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
 * If rememberDecisions is enabled and the host supports ui.select, offers
 * three choices: session allow, permanent allow, deny.  Otherwise falls
 * back to a simple confirm() (allow / deny).
 *
 * Returns: { ok, remember } where ok=false means the user denied.
 */
export async function confirmWithRemember(
  ctx: ExtensionCtx,
  title: string,
  body: string,
  t: I18n,
  rememberDecisions: boolean,
): Promise<{ ok: boolean; remember: RememberChoice }> {
  // If remember is disabled or UI doesn't support select, use simple confirm
  if (!rememberDecisions || typeof ctx.ui.select !== "function") {
    const ok = await ctx.ui.confirm(title, body);
    return { ok, remember: "none" };
  }

  const denyLabel = "❌ " + (ctx.lang === "zh" ? "拒绝" : "Deny");
  const choices = [t.sessionAllow, t.permanentAllow, denyLabel];
  const choice = await ctx.ui.select(title + "\n\n" + body, choices);

  // OMP resolves select() with the option label (string), not an index.
  // Accept both string-label and numeric-index for robustness across hosts.
  if (choice === t.sessionAllow || choice === 0) return { ok: true, remember: "session" };
  if (choice === t.permanentAllow || choice === 1) return { ok: true, remember: "permanent" };
  if (choice === denyLabel || choice === 2) return { ok: false, remember: "none" };
  // Undefined / null / anything else → treat as deny (fail-closed).
  return { ok: false, remember: "none" };
}
