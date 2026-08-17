/**
 * Smart Approve — configuration.
 *
 * Loads JSON config from ~/.omp/agent/smart-approve.json (or ~/.pi/agent/...)
 * and deep-merges over defaults.  Encapsulates config + paths so callers
 * don't repeat directory-resolution logic.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { LoggerLike } from "./logger";
import { DEFAULT_PROTECTED_PATHS } from "./paths";

export type ApprovalMode = "interactive" | "auto";
export type AutoFallback = "regex" | "block";
export type AutoBlockRisk = "high" | "medium";

export interface SmartApproveConfig {
  enabled: boolean;
  /** Approval flow: interactive (dialogs) or auto (AI decides, no dialogs). */
  mode: ApprovalMode;
  /** Auto mode: AI verdict at or above this risk level blocks. */
  autoBlockRisk: AutoBlockRisk;
  /** Auto mode: what to do when the LLM chain fails entirely. */
  autoFallback: AutoFallback;
  /** Auto mode: subagent sessions (no UI) also use AI decisions. */
  autoInHeadless: boolean;
  /** Per-tool coverage toggles. */
  coverage: { eval: boolean };
  /** Protected path glob patterns for write/edit interception. */
  protectedPaths: string[];
  /** Whether to run LLM risk analysis (requires host binary). */
  llmAnalysis: boolean;
  /** Whether to remember decisions. */
  rememberDecisions: boolean;
  /** Max characters of session context to feed the LLM. */
  contextMaxChars: number;
  /** Timeout for the one-shot LLM risk analysis, in milliseconds.
   *  0 = no timeout (analysis can hang indefinitely). Default 30s. */
  analysisTimeoutMs: number;
  /** Idle lifetime of the persistent RPC child, in milliseconds.
   *  After this long without a prompt the child is killed (freed memory);
   *  the next analysis lazily respawns it. 0 = keep alive until session end.
   *  Default 10 minutes. */
  rpcIdleTimeoutMs: number;
  /** Model spec for the one-shot risk analysis. Accepts any string the omp
   *  --model flag accepts: role alias (@tiny / @smol / @slow), provider/id,
   *  or bare id. Default @tiny — the cheapest role, first in the fallback
   *  chain @tiny -> @smol -> @default. */
  model: string;
}

const DEFAULT_CONFIG: SmartApproveConfig = {
  enabled: true,
  mode: "interactive",
  autoBlockRisk: "high",
  autoFallback: "regex",
  autoInHeadless: false,
  coverage: { eval: true },
  protectedPaths: DEFAULT_PROTECTED_PATHS,
  llmAnalysis: true,
  rememberDecisions: true,
  contextMaxChars: 3000,
  analysisTimeoutMs: 30_000,
  rpcIdleTimeoutMs: 600_000,
  model: "@tiny",
};

/** Deep-merge user config over defaults (arrays replaced, not concatenated). */
function mergeConfig(user: unknown): SmartApproveConfig {
  if (!user || typeof user !== "object") return { ...DEFAULT_CONFIG };
  const u = user as Record<string, unknown>;
  const coverage = (
    u.coverage && typeof u.coverage === "object"
      ? u.coverage as Record<string, unknown>
      : {}
  );
  return {
    enabled: typeof u.enabled === "boolean" ? u.enabled : DEFAULT_CONFIG.enabled,
    mode: u.mode === "auto" ? "auto" : DEFAULT_CONFIG.mode,
    autoBlockRisk: u.autoBlockRisk === "medium" ? "medium" : DEFAULT_CONFIG.autoBlockRisk,
    autoFallback: u.autoFallback === "block" ? "block" : DEFAULT_CONFIG.autoFallback,
    autoInHeadless: typeof u.autoInHeadless === "boolean"
      ? u.autoInHeadless
      : DEFAULT_CONFIG.autoInHeadless,
    coverage: {
      eval: typeof coverage.eval === "boolean" ? coverage.eval : DEFAULT_CONFIG.coverage.eval,
    },
    protectedPaths: Array.isArray(u.protectedPaths) ? u.protectedPaths as string[] : DEFAULT_CONFIG.protectedPaths,
    llmAnalysis: typeof u.llmAnalysis === "boolean" ? u.llmAnalysis : DEFAULT_CONFIG.llmAnalysis,
    rememberDecisions: typeof u.rememberDecisions === "boolean" ? u.rememberDecisions : DEFAULT_CONFIG.rememberDecisions,
    contextMaxChars: typeof u.contextMaxChars === "number" ? u.contextMaxChars : DEFAULT_CONFIG.contextMaxChars,
    analysisTimeoutMs: typeof u.analysisTimeoutMs === "number" && u.analysisTimeoutMs >= 0
      ? u.analysisTimeoutMs
      : DEFAULT_CONFIG.analysisTimeoutMs,
    rpcIdleTimeoutMs: typeof u.rpcIdleTimeoutMs === "number" && u.rpcIdleTimeoutMs >= 0
      ? u.rpcIdleTimeoutMs
      : DEFAULT_CONFIG.rpcIdleTimeoutMs,
    model: typeof u.model === "string" && u.model.trim() ? u.model.trim() : DEFAULT_CONFIG.model,
  };
}

/** Resolve config directory: ~/.omp/agent or ~/.pi/agent. */
export function getConfigDir(): string {
  const home = os.homedir();
  const ompDir = path.join(home, ".omp", "agent");
  const piDir = path.join(home, ".pi", "agent");
  if (fs.existsSync(ompDir)) return ompDir;
  if (fs.existsSync(piDir)) return piDir;
  return ompDir;
}

/** Keys that may be changed at runtime (written back to disk on persist). */
const PERSISTABLE_KEYS: readonly (keyof SmartApproveConfig)[] = [
  "mode", "autoBlockRisk", "autoFallback", "autoInHeadless", "coverage",
];

/**
 * Configuration store.  Loads once at construction; exposes typed accessors,
 * runtime mutation (update) and selective write-back (persist) so slash
 * commands can change the approval mode without clobbering user-edited
 * fields in the config file.
 */
export class ConfigStore {
  readonly config: SmartApproveConfig;
  readonly configPath: string;
  readonly allowListPath: string;
  private readonly dirty = new Set<keyof SmartApproveConfig>();

  constructor(private readonly logger?: LoggerLike, configDir?: string) {
    const dir = configDir ?? getConfigDir();
    this.configPath = path.join(dir, "smart-approve.json");
    this.allowListPath = path.join(dir, "smart-approve-allow.json");
    this.config = this.load();
  }

  private load(): SmartApproveConfig {
    try {
      if (fs.existsSync(this.configPath)) {
        const raw = fs.readFileSync(this.configPath, "utf-8");
        const merged = mergeConfig(JSON.parse(raw));
        this.logger?.log(`config loaded: ${this.configPath}`);
        return merged;
      }
    } catch (e) {
      this.logger?.log(`config load failed, using defaults: ${e instanceof Error ? e.message : String(e)}`);
    }
    return { ...DEFAULT_CONFIG };
  }

  /** Apply a partial change to the in-memory config (immediate effect).
   *  Keys marked persistable are remembered and written back by persist(). */
  update(partial: Partial<SmartApproveConfig>): void {
    for (const key of PERSISTABLE_KEYS) {
      const value = partial[key];
      if (value === undefined) continue;
      Object.assign(this.config, { [key]: value });
      this.dirty.add(key);
    }
    this.logger?.log(`config updated: ${[...this.dirty].join(",")}`);
  }

  /** Write dirty runtime changes back to the config file, preserving every
   *  other user-authored key.  Never throws — persistence is best-effort. */
  persist(): void {
    if (this.dirty.size === 0) return;
    try {
      let raw: Record<string, unknown> = {};
      if (fs.existsSync(this.configPath)) {
        const parsed: unknown = JSON.parse(fs.readFileSync(this.configPath, "utf-8"));
        if (parsed && typeof parsed === "object") raw = parsed as Record<string, unknown>;
      }
      for (const key of this.dirty) raw[key] = this.config[key];
      const dir = path.dirname(this.configPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.configPath, JSON.stringify(raw, null, 2), "utf-8");
      this.dirty.clear();
      this.logger?.log(`config persisted: ${this.configPath}`);
    } catch (e) {
      this.logger?.log(`config persist failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

