/**
 * Smart Approve — runtime mode manager.
 *
 * Owns dynamic switching between interactive / auto approval mode from
 * the TUI slash command.  Changes apply immediately in memory and are
 * selectively persisted by ConfigStore so they survive restarts without
 * clobbering other user-edited config fields.
 */

import type { ConfigStore } from "./config";
import type { ApprovalMode } from "./config";
import type { LoggerLike } from "./logger";

/** Coverage summary shown by the status command. */
export interface CoverageSummary {
  eval: boolean;
  hub: boolean;
}

export class ModeManager {
  constructor(
    private readonly configStore: ConfigStore,
    private readonly logger: LoggerLike,
    private readonly coverage: CoverageSummary,
  ) {}

  /** Flip interactive <-> auto.  Returns the new mode. */
  toggle(): ApprovalMode {
    const next: ApprovalMode = this.configStore.config.mode === "auto" ? "interactive" : "auto";
    return this.set(next);
  }

  /** Switch to a specific mode (no-op when already there). */
  set(mode: ApprovalMode): ApprovalMode {
    this.configStore.update({ mode });
    this.configStore.persist();
    this.logger.log(`mode-manager: switched to ${mode}`);
    return mode;
  }

  /** Human-readable status block for `/smart-approve status`. */
  status(): string {
    const c = this.configStore.config;
    return [
      `mode: ${c.mode}`,
      `autoBlockRisk: ${c.autoBlockRisk}`,
      `autoFallback: ${c.autoFallback}`,
      `autoInHeadless: ${c.autoInHeadless}`,
      `llmAnalysis: ${c.llmAnalysis}`,
      `coverage: eval=${this.coverage.eval} hub=${this.coverage.hub}`,
    ].join("\n");
  }
}
