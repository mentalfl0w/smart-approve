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
import type { Logger } from "./logger";
import { DEFAULT_PROTECTED_PATHS } from "./paths";

export interface SmartApproveConfig {
  enabled: boolean;
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
  return {
    enabled: typeof u.enabled === "boolean" ? u.enabled : DEFAULT_CONFIG.enabled,
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

/**
 * Configuration store.  Loads once at construction; exposes typed accessors
 * and the derived allow-list path.
 */
export class ConfigStore {
  readonly config: SmartApproveConfig;
  readonly configPath: string;
  readonly allowListPath: string;

  constructor(private readonly logger?: Logger) {
    const dir = getConfigDir();
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
}
