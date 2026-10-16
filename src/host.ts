/**
 * Smart Approve — chat and host-native model adapters.
 *
 * Chat models use a persistent RPC child. Registered Pi classifiers and OMP
 * judges use their host model registries and native request APIs.
 */

import * as fs from "node:fs";
import { execSync } from "node:child_process";
import type { ExtensionCtx, RiskAnalysis } from "./types";
import type { I18n } from "./i18n";
import type { Logger } from "./logger";
import { RpcModelInvoker } from "./rpc-invoker";
import { shouldRetryFresh } from "./analysis-policy";
import { NativeDecisionProtocol } from "./native-decision-protocol";
import { OmpNativeJudgeDecisionAdapter } from "./omp-native-judge-adapter";
import { PiClassifierDecisionAdapter } from "./pi-classifier-adapter";
import type { OmpNativeJudgmentSupportLoader } from "./omp-native-judge-adapter";

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
 * Routes registered native decision models to their host API and chat models
 * to the persistent `omp --mode rpc` fallback chain.
 *
 * Native model failures return no verdict; interactive confirmation and
 * autoFallback remain owned by ToolGate and AutoDecisionPolicy.
 */
export class ModelInvoker {
  private readonly host: HostResolver;
  private readonly logger: Logger;
  private readonly timeoutMs: number;
  private readonly rpcIdleTimeoutMs: number;
  private rpc: RpcModelInvoker | null = null;
  private readonly piClassifierAdapter: PiClassifierDecisionAdapter;
  private readonly ompNativeJudgeAdapter: OmpNativeJudgeDecisionAdapter;

  /** @param timeoutMs Bounded wait per model attempt (0 = no timeout).
   *  @param rpcIdleTimeoutMs Reap the RPC child after this long idle (0 = keep alive). */
  constructor(
    host: HostResolver,
    logger: Logger,
    timeoutMs: number,
    rpcIdleTimeoutMs: number,
    ompSupportLoader?: OmpNativeJudgmentSupportLoader,
  ) {
    this.host = host;
    this.logger = logger;
    this.timeoutMs = timeoutMs;
    this.rpcIdleTimeoutMs = rpcIdleTimeoutMs;
    const nativeProtocol = new NativeDecisionProtocol();
    this.piClassifierAdapter = new PiClassifierDecisionAdapter(nativeProtocol, timeoutMs, logger);
    this.ompNativeJudgeAdapter = new OmpNativeJudgeDecisionAdapter(
      nativeProtocol,
      timeoutMs,
      logger,
      ompSupportLoader,
    );
  }

  /** Run the configured model on a prompt, parse JSON, return the analysis. */
  async invoke(
    prompt: string,
    model: string,
    signal?: AbortSignal,
    ompHost = false,
  ): Promise<RiskAnalysis | null> {
    const bin = this.host.resolve();
    if (!bin) return null;

    // Lazy-spawn the persistent RPC child on first use.
    this.rpc ??= new RpcModelInvoker(bin, this.logger, this.rpcIdleTimeoutMs, ompHost);

    const run = async (m: string): Promise<string | null> => {
      this.logger.log(`runOneShotModel: rpc prompt model=${m}`);
      return this.rpc!.prompt(m, prompt, {
        timeoutMs: this.timeoutMs,
        signal,
      });
    };

    try {
      // Attempt chain: configured model first, then the standard fallbacks
      // @tiny -> @smol -> @default, deduped. A spec that cannot spawn (e.g.
      // a role alias absent from the host's modelRoles) fails fast and is
      // skipped; a rejected spawn must not abort the whole analysis.
      const chain = [...new Set([model, "@tiny", "@smol", "@default"])];

      let text: string | null = null;
      for (const m of chain) {
        if (signal?.aborted) break;
        try {
          text = await run(m);
        } catch (e) {
          this.logger.log(`runOneShotModel: ${m} spawn failed (${e instanceof Error ? e.message : String(e)}), skipping`);
          continue;
        }
        if (text) break;
        // First attempt returned no text — a reused --no-session child can
        // settle without assistant text. Retry the configured model once on
        // a fresh child before falling through the chain.
        if (m === model && shouldRetryFresh(text, signal?.aborted === true)) {
          this.logger.log(`runOneShotModel: ${m} returned no text, retrying on a fresh child`);
          this.rpc!.kill();
          try {
            text = await run(m);
          } catch (e) {
            this.logger.log(`runOneShotModel: ${m} fresh-child retry failed (${e instanceof Error ? e.message : String(e)})`);
            text = null;
          }
          if (text) break;
        }
        this.logger.log(`runOneShotModel: ${m} failed, trying next in chain`);
      }

      if (!text) {
        this.logger.log("runOneShotModel: all models in chain failed");
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
    this.rpc?.dispose();
    this.rpc = null;
  }

  /** Analyze one command or code block using the selected host model. */
  async analyze(
    subject: string,
    subjectLabel: string,
    behaviorLabels: string[],
    contextSection: string,
    t: I18n,
    model: string,
    signal?: AbortSignal,
    ctx?: ExtensionCtx,
  ): Promise<RiskAnalysis | null> {
    if (ctx?.modelRegistry) {
      const input = { subject, subjectLabel, behaviorLabels, contextSection };
      const piAttempt = await this.piClassifierAdapter.tryAnalyze(
        ctx.modelRegistry, model, input, t, signal,
      );
      if (piAttempt.matched) return piAttempt.analysis;

      const ompAttempt = await this.ompNativeJudgeAdapter.tryAnalyze(
        ctx.modelRegistry, model, input, t, signal,
      );
      if (ompAttempt.matched) return ompAttempt.analysis;
    }

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
      `=== ${subjectLabel} ===`,
      subject,
      "",
      t.promptOutput,
      '- risk: "low" | "medium" | "high"',
      `- summary: ${t.promptSummaryDesc}`,
      `- detail: ${t.promptDetailDesc}`,
      `- recommend: ${t.promptRecommendDesc}`,
      "",
      t.promptOnlyJson,
    ].join("\n");

    const isOmpHost = typeof ctx?.modelRegistry?.find === "function";
    return this.invoke(prompt, model, signal, isOmpHost);
  }
}

