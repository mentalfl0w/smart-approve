/**
 * Smart Approve — persistent RPC model invoker.
 *
 * Spawns ONE `omp --mode rpc` child process and reuses it for every
 * one-shot risk analysis, instead of cold-starting `omp -p` per call.
 * This amortizes extension loading (provider-retry-proxy, etc.) and
 * process startup across analyses.
 *
 * Protocol (docs/rpc.md):
 *   - `prompt` is acknowledged immediately; completion arrives via
 *     `agent_end` (messages) events
 *   - `abort` cancels the in-flight prompt (user interruption)
 *   - model switching (e.g. @smol -> @default) respawns the child with
 *     `--model`, since RPC `set_model` needs provider/modelId while our
 *     specs are role aliases
 *
 * The child is lazily spawned on first use and killed on session
 * shutdown. A crashed child is respawned on the next call.
 */

import * as child_process from "node:child_process";
import * as readline from "node:readline";
import type { Logger } from "./logger";
import {
  enqueueSerialized,
  extractAssistantText,
  shouldClearProcRef,
  shouldSettleAgentEnd,
} from "./analysis-policy";

interface RpcFrame {
  type: string;
  id?: string;
  command?: string;
  success?: boolean;
  error?: string;
  protocolVersion?: number;
  messages?: unknown;
  [k: string]: unknown;
}

interface PendingPrompt {
  resolve: (text: string | null) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  /** Accumulated text_delta deltas from message_update frames, used when
   *  agent_end.messages carries no assistant text. */
  deltaBuffer: string;
}

export class RpcModelInvoker {
  private proc: child_process.ChildProcess | null = null;
  private rl: readline.Interface | null = null;
  private spawnPromise: Promise<void> | null = null;
  private currentModel: string | null = null;
  private seq = 0;
  private pending: PendingPrompt | null = null;
  private chain: Promise<string | null> = Promise.resolve(null);
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly bin: string;
  private readonly logger: Logger;
  private readonly idleTimeoutMs: number;

  /** @param idleTimeoutMs Reap the child after this long without prompts (0 = keep alive). */
  constructor(bin: string, logger: Logger, idleTimeoutMs: number) {
    this.bin = bin;
    this.logger = logger;
    this.idleTimeoutMs = idleTimeoutMs;
  }

  /** True when a spawn attempt has been made and the process is alive. */
  get isAlive(): boolean {
    return !!this.proc && this.proc.exitCode === null && this.proc.signalCode === null;
  }

  /** Run a one-shot prompt on the given model spec. Returns raw text or null. */
  prompt(model: string, promptText: string, opts: {
    timeoutMs: number;
    signal?: AbortSignal;
  }): Promise<string | null> {
    // Serialize prompts: one analysis at a time over the shared connection.
    // A rejected prior spawn must not poison this prompt.
    this.chain = enqueueSerialized(this.chain, () => this.runPrompt(model, promptText, opts));
    return this.chain;
  }

  /** Kill the child process (session shutdown, model switch, or idle reap). */
  kill(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    if (this.proc && this.isAlive) {
      this.logger.log("rpc: killing model invoker process");
      this.proc.kill("SIGTERM");
    }
    this.proc = null;
    this.rl?.close();
    this.rl = null;
    this.pending = null;
    this.spawnPromise = null;
  }

  // ── internals ─────────────────────────────────────────────────────

  private async runPrompt(
    model: string,
    promptText: string,
    opts: { timeoutMs: number; signal?: AbortSignal },
  ): Promise<string | null> {
    if (opts.signal?.aborted) return null;

    // Ensure the child runs with the requested model; respawn on spec change.
    // (When the model matches and the child is healthy, reuse it as-is —
    // extension loading and startup are paid once per host session.)
    if (model !== this.currentModel || !this.isAlive) {
      this.logger.log(`rpc: model change ${this.currentModel ?? "(none)"} -> ${model}, restarting`);
      this.kill();
      this.spawnPromise = this.spawn(model);
      await this.spawnPromise;
    }

    // Cancel any pending idle reap — the child is active again.
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }

    const id = `sa-${++this.seq}`;
    this.logger.log(`rpc: prompt ${id} model=${model}`);

    const { promise, resolve } = Promise.withResolvers<string | null>();
    const pending: PendingPrompt = { resolve, timer: undefined, deltaBuffer: "" };
    this.pending = pending;

    // Reap the child after the idle window if no further prompt arrives.
    if (opts.timeoutMs > 0) {
      pending.timer = setTimeout(() => {
        this.logger.log(`rpc: prompt ${id} timed out after ${opts.timeoutMs}ms, aborting`);
        this.abort();
      }, opts.timeoutMs);
    }

    promise.finally(() => {
      // Prompt settled — arm the idle reaper for the next quiet window.
      if (this.idleTimeoutMs > 0) {
        this.idleTimer = setTimeout(() => {
          this.logger.log(`rpc: idle ${this.idleTimeoutMs}ms, reaping child`);
          this.kill();
        }, this.idleTimeoutMs);
      }
    });

    const onAbort = () => {
      this.logger.log(`rpc: prompt ${id} aborted by signal`);
      this.abort();
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }

    this.write({
      id,
      type: "prompt",
      message: promptText,
    });

    return promise;
  }

  /** Spawn the RPC child and wait for the ready frame. */
  private spawn(model: string): Promise<void> {
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const proc = child_process.spawn(this.bin, [
      "--mode", "rpc",
      "--model", model,
      "--no-tools",
      "--no-session",
      "--no-lsp",
      "--no-skills",
      "--no-rules",
      "--no-title",
      "--no-prewalk",
      "--no-pty",
      "--no-extensions",
      "--thinking=off",
      "--max-time=300",
    ], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, PI_MEMORY_BACKEND: "off" },
    });
    this.proc = proc;
    this.currentModel = model;
    this.logger.log(`rpc: spawned ${this.bin} --mode rpc --model ${model} pid=${proc.pid}`);

    let stderrBuf = "";
    proc.stderr?.on("data", (d: Buffer) => {
      stderrBuf = (stderrBuf + d.toString()).slice(-2000);
    });

    const rl = readline.createInterface({ input: proc.stdout!, crlfDelay: Infinity });
    this.rl = rl;

    let ready = false;
    const onLine = (line: string) => {
      let frame: RpcFrame;
      try {
        frame = JSON.parse(line);
      } catch {
        return;
      }
      if (!ready) {
        if (frame.type === "ready") {
          ready = true;
          this.logger.log(`rpc: ready protocol=${frame.protocolVersion}`);
          resolve();
        }
        // ignore pre-ready frames
        return;
      }
      this.handleFrame(frame);
    };
    rl.on("line", onLine);

    proc.on("error", (err) => {
      this.logger.log(`rpc: spawn error: ${err.message}`);
      if (shouldClearProcRef(this.proc, proc)) {
        this.proc = null;
        this.rl = null;
        this.spawnPromise = null;
      }
      if (!ready) reject(err);
      else this.failPending(`process error: ${err.message}`);
    });
    proc.on("exit", (code, signal) => {
      this.logger.log(`rpc: process exited code=${code} signal=${signal} stderr=${stderrBuf.slice(-500)}`);
      if (shouldClearProcRef(this.proc, proc)) {
        this.proc = null;
        this.rl = null;
        this.spawnPromise = null;
        if (!ready) reject(new Error(`rpc process exited before ready (code ${code})`));
        else this.failPending(`process exited (code ${code})`);
      }
    });
    return promise;
  }

  /** Dispatch an inbound frame after ready. */
  private handleFrame(frame: RpcFrame): void {
    switch (frame.type) {
      case "response": {
        if (frame.command === "prompt") {
          const agentInvoked = (frame.data as { agentInvoked?: boolean } | undefined)?.agentInvoked;
          if (agentInvoked === false) {
            // Local-only completion: no agent turn will start, so no
            // agent_end will arrive. Settle now instead of waiting out
            // the timeout.
            this.logger.log("rpc: prompt resolved locally (agentInvoked=false)");
            this.settle(null);
          } else if (frame.success !== true) {
            this.logger.log(`rpc: prompt rejected: ${frame.error}`);
            this.settle(null);
          }
        }
        break;
      }
      case "message_update": {
        // Accumulate streaming text deltas so an agent_end with an empty
        // messages array (the canonical protocol shape) still yields text.
        const ev = (frame as { assistantMessageEvent?: { type?: string; delta?: string } }).assistantMessageEvent;
        if (ev?.type === "text_delta" && typeof ev.delta === "string" && this.pending) {
          this.pending.deltaBuffer += ev.delta;
        }
        break;
      }
      case "agent_end": {
        if (!shouldSettleAgentEnd({ isTerminal: frame.isTerminal })) {
          this.logger.log("rpc: ignoring non-terminal agent_end");
          break;
        }
        const text = extractAssistantText(frame.messages, this.pending?.deltaBuffer ?? "");
        if (!text) {
          this.logger.log("rpc: agent_end with no assistant text");
        }
        this.settle(text || null);
        break;
      }
      case "prompt_result": {
        if ((frame as { agentInvoked?: boolean }).agentInvoked === false) {
          this.logger.log("rpc: prompt resolved locally (prompt_result)");
          this.settle(null);
        }
        break;
      }
      case "extension_error":
        this.logger.log(`rpc: extension_error: ${String(frame.error ?? "")}`);
        break;
      default:
        break;
    }
  }

  /** Settle the in-flight prompt. */
  private settle(text: string | null): void {
    const p = this.pending;
    if (!p) return;
    this.pending = null;
    clearTimeout(p.timer);
    p.resolve(text);
  }

  /** Fail the in-flight prompt (process death). */
  private failPending(reason: string): void {
    const p = this.pending;
    this.pending = null;
    clearTimeout(p?.timer);
    this.logger.log(`rpc: prompt failed: ${reason}`);
    p?.resolve(null);
  }

  /** Send abort for the in-flight prompt. */
  private abort(): void {
    this.write({ type: "abort" });
    // If the process never settles (e.g. stuck), force-fail after a grace period.
    const p = this.pending;
    if (p) {
      setTimeout(() => this.settle(null), 5000);
    }
  }

  /** Write one JSONL frame to the child stdin. */
  private write(frame: RpcFrame): void {
    if (!this.proc?.stdin?.writable) return;
    this.proc.stdin.write(JSON.stringify(frame) + "\n");
  }
}
