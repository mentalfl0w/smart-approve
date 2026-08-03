/**
 * Smart Approve — host resolution + one-shot LLM invocation.
 *
 * Resolves the host binary path (the process that launched this extension)
 * and runs the smol model in print mode for risk analysis.  All diagnostic
 * detail flows through the Logger so failures are traceable end-to-end.
 */

import * as fs from "node:fs";
import { execSync } from "node:child_process";
import type { ExtensionAPI, ExecResult, RiskAnalysis } from "./types";
import type { I18n } from "./i18n";
import type { Logger } from "./logger";
import { RpcModelInvoker } from "./rpc-invoker";

/** Extract JSON object from model output (handles ```json fences and bare JSON). */
function extractJson(text: string): RiskAnalysis | null {
  if (!text) return null;
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fenced ? fenced[1] : text;
  const m = raw.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try { return JSON.parse(m[0]); } catch { return null; }
}

/**
 * Resolves the host binary path for one-shot model invocation.
 *
 * Strategy (in priority order):
 *  1. process.execPath — the real runtime binary path (e.g.
 *     /opt/homebrew/Cellar/omp/17.0.9/bin/omp).  Works even when the
 *     host is a Bun-bundled single binary, where process.argv[1] is a
 *     virtual FS path like /$bunfs/root/... that cannot be realpath'd.
 *  2. process.argv[1] — the host binary that launched this extension.
 *     Works for non-bundled hosts; realpath'd to resolve symlinks.
 *  3. PATH lookup via `command -v omp` / `command -v pi` — last resort.
 *     May fail if the extension process inherits a sanitized PATH.
 *
 * Memoized after first resolution.
 */
export class HostResolver {
  private resolved: string | null | undefined;
  private readonly logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /** Resolve and memoize the host binary path. */
  resolve(): string | null {
    if (this.resolved !== undefined) return this.resolved;

    // 1. process.execPath — most reliable for bundled binaries
    this.resolved = this.tryResolve("process.execPath", process.execPath);
    if (this.resolved) return this.resolved;

    // 2. process.argv[1] — for non-bundled hosts
    this.resolved = this.tryResolve("process.argv[1]", process.argv[1]);
    if (this.resolved) return this.resolved;

    // 3. PATH lookup — last resort
    this.resolved = this.tryPathLookup();
    if (this.resolved) return this.resolved;

    this.logger.log("getHostBin: all strategies failed");
    this.resolved = null;
    return null;
  }

  /** Try to realpath a candidate; log + return null on failure. */
  private tryResolve(strategy: string, candidate: string | undefined): string | null {
    if (!candidate) {
      this.logger.log(`getHostBin: ${strategy} is empty`)
      return null
    }
    try {
      const resolved = fs.realpathSync(candidate)
      this.logger.log(`getHostBin: ${strategy} resolved ${resolved}`)
      return resolved
    } catch (e) {
      this.logger.log(`getHostBin: ${strategy} FAILED: ${e instanceof Error ? e.message : String(e)}`)
      return null
    }
  }

  /** PATH lookup via `command -v omp` / `command -v pi`. */
  private tryPathLookup(): string | null {
    for (const bin of ["omp", "pi"]) {
      try {
        const out = execSync(`command -v ${bin}`, {
          stdio: ["pipe", "pipe", "ignore"],
          timeout: 2000,
          encoding: "utf-8",
        });
        const resolved = out.trim();
        // Resolve to an absolute path — a bare name would fail to spawn
        // in worker processes with an incomplete PATH (posix_spawn ENOENT).
        if (resolved && resolved.includes("/")) {
          this.logger.log(`getHostBin: PATH lookup resolved ${resolved}`);
          return resolved;
        }
      } catch {
        // not found
      }
    }
    this.logger.log("getHostBin: PATH lookup failed for omp and pi");
    return null;
  }
}

/**
 * Runs one-shot model invocations via the host binary's print mode.
 *
 * The model spec comes from SmartApproveConfig (defaulting to @smol).
 * No timeout is applied — the subprocess runs to completion. In the
 * custom tool's execute() path there is no 30s pressure. If @smol is
 * unconfigured, falls back to @default automatically.
 */
export class ModelInvoker {
  private readonly host: HostResolver;
  private readonly logger: Logger;
  private readonly timeoutMs: number;
  private rpc: RpcModelInvoker | null = null;

  /** @param timeoutMs Bounded wait per model attempt (0 = no timeout). */
  constructor(host: HostResolver, logger: Logger, timeoutMs: number) {
    this.host = host;
    this.logger = logger;
    this.timeoutMs = timeoutMs;
  }

  /** Run the configured model on a prompt, parse JSON, return the analysis. */
  async invoke(
    pi: ExtensionAPI,
    prompt: string,
    model: string,
    signal?: AbortSignal,
  ): Promise<RiskAnalysis | null> {
    const bin = this.host.resolve();
    if (!bin) return null;

    // Lazy-spawn the persistent RPC child on first use.
    this.rpc ??= new RpcModelInvoker(bin, this.logger);

    const run = async (m: string): Promise<string | null> => {
      this.logger.log(`runOneShotModel: rpc prompt model=${m}`);
      return this.rpc!.prompt(m, prompt, {
        timeoutMs: this.timeoutMs,
        signal,
      });
    };

    try {
      let text = await run(model);
      // Fallback: if @smol role is unconfigured or the call failed
      // (including timeout), retry with @default. Each attempt has its
      // own bounded timeout, so the retry cannot hang indefinitely either.
      if (!text && model === "@smol") {
        this.logger.log(`runOneShotModel: @smol failed, retrying with @default`);
        text = await run("@default");
      }

      if (!text) {
        this.logger.log("runOneShotModel: no output from model");
        return null;
      }
      const parsed = extractJson(text);
      if (!parsed) {
        this.logger.log(`runOneShotModel: could not parse JSON from output (first 200 chars): ${text.slice(0, 200)}`);
      }
      return parsed as RiskAnalysis | null;
    } catch (e) {
      this.logger.log(`runOneShotModel FAILED: ${e instanceof Error ? e.message : String(e)}`);
      return null;
    }
  }

  /** Shut down the persistent RPC child (session shutdown). */
  dispose(): void {
    this.rpc?.kill();
    this.rpc = null;
  }

  /**
   * Build the risk-analysis prompt from a pre-formatted context section,
   * behavior labels, and the command, then invoke the model.
   *
   * The caller formats session context (via SessionContextGatherer.format)
   * so this method stays focused on prompt assembly + invocation.
   */
  async analyze(
    pi: ExtensionAPI,
    cmd: string,
    behaviorLabels: string[],
    contextSection: string,
    t: I18n,
    model: string,
    signal?: AbortSignal,
  ): Promise<RiskAnalysis | null> {
    const behaviorText = behaviorLabels.length > 0
      ? behaviorLabels.join("; ")
      : "none detected";

    const prompt = [
      t.promptIntro,
      "",
      `=== ${t.promptContext} ===`,
      contextSection,
      `=== ${t.promptRule} ===`,
      behaviorText,
      "",
      `=== ${t.promptCommand} ===`,
      cmd,
      "",
      t.promptOutput,
      '- risk: "low" | "medium" | "high"',
      `- summary: ${t.promptSummaryDesc}`,
      `- detail: ${t.promptDetailDesc}`,
      `- recommend: ${t.promptRecommendDesc}`,
      "",
      t.promptOnlyJson,
    ].join("\n");

    return this.invoke(pi, prompt, model, signal);
  }

}
