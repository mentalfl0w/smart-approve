/**
 * Smart Approve — type definitions.
 *
 * Extension API surface, tool-call event/ctx shapes, and the risk-analysis
 * result contract returned by the smol LLM.  Kept free of runtime code so
 * every other module can import the contracts it needs without pulling in
 * side-effecting state.
 */

// ── Extension API surface (minimal; no host import) ──────────────────

/** The pi/omp extension API surface used by this extension. */
export interface ExtensionAPI {
  on(
    event: "tool_call" | "session_shutdown",
    handler: (
      event: ToolCallEvent,
      ctx: ExtensionCtx,
    ) => Promise<void | { block: true; reason: string }>,
  ): void;
  exec(
    bin: string,
    args: string[],
    opts?: Record<string, unknown>,
  ): Promise<{ code: number; stdout: string; stderr: string }>;
}

export interface ToolCallEvent {
  toolName: string;
  toolCallId?: string;
  input: { command?: string; path?: string; [k: string]: unknown };
}

export interface ExtensionCtx {
  hasUI: boolean;
  cwd?: string;
  lang?: string;
  sessionManager?: {
    getBranch?: () => unknown[];
    getEntries?: () => unknown[];
  };
  ui: {
    confirm: (title: string, body: string) => Promise<boolean>;
    // OMP's ui.select resolves with the chosen option's label (string), not a
    // numeric index. In no-UI/headless contexts it resolves with undefined.
    select?: (title: string, choices: string[]) => Promise<string | number | undefined>;
    setStatus: (id: string, text: string | undefined) => void;
    notify?: (msg: string, level: "info" | "warning") => void;
  };
}

// ── Domain value objects ─────────────────────────────────────────────

/** Model analysis result from the smol LLM. */
export interface RiskAnalysis {
  risk?: string;
  summary?: string;
  detail?: string;
  recommend?: string;
}

/** A detected risky behavior with localized labels. */
export interface Behavior {
  id: string;
  label: { en: string; zh: string };
}

/** Composite danger analysis for a bash command. */
export interface DangerAnalysis {
  /** Detected behavior ids (deduped). */
  behaviors: string[];
  /** Localized labels for display. */
  labels: { en: string; zh: string }[];
  /** True if any matched behavior is in the hard-block set. */
  hardBlocked: boolean;
}

/** A persisted or in-memory allow-list decision. */
export interface AllowEntry {
  /** "bash", "write", or "edit". */
  tool: string;
  /** Normalized command (for bash) or resolved path (for write/edit). */
  key: string;
  /** cwd at time of allow, for scoping. */
  cwd: string;
  /** ISO timestamp of the decision. */
  timestamp: string;
}

/** Compact excerpts of the agent's conversation history fed to the LLM. */
export interface SessionContext {
  firstUser: string | null;
  recentAssistant: string[];
}

/** A remember-this-decision outcome from the confirmation dialog. */
export type RememberChoice = "none" | "session" | "permanent";
