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
  /** Execute a shell command. */
  exec(command: string, args: string[], options?: ExecOptions): Promise<ExecResult>;
  /** Register a custom tool callable by the LLM. */
  registerTool<TParams = unknown, TDetails = unknown>(tool: ToolDefinition<TParams, TDetails>): void;
  /** Injected zod module for tool parameter schemas (runtime-injected by host). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  zod: any;
}

/** Minimal exec options (subset of Node/Bun exec). */
export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeout?: number;
  signal?: AbortSignal;
}

/** Minimal exec result. */
export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  killed?: boolean;
}

/** Tool definition for registerTool. */
export interface ToolDefinition<TParams = unknown, TDetails = unknown> {
  name: string;
  label?: string;
  description: string;
  parameters: unknown;
  approval?: string;
  deferrable?: boolean;
  hidden?: boolean;
  execute(
    toolCallId: string,
    params: TParams,
    signal: AbortSignal | undefined,
    onUpdate: ((update: { content: unknown[]; details?: unknown }) => void) | undefined,
    ctx: ExtensionCtx,
  ): Promise<AgentToolResult<TDetails>>;
  onSession?: (event: { reason: string }, ctx: ExtensionCtx) => void | Promise<void>;
}

/** Tool result returned by custom tool execute(). */
export interface AgentToolResult<TDetails = unknown> {
  content: Array<{ type: "text"; text: string }>;
  details?: TDetails;
  isError?: boolean;
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
