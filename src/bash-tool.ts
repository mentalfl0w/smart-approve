/**
 * Smart Approve — custom "bash" tool.
 *
 * Replaces OMP's built-in bash tool with a smart-approve-aware version.
 * execute() is NOT subject to EXTENSION_HANDLER_TIMEOUT_MS (30s) — that
 * timeout only wraps the tool_call event handler dispatch. This means
 * the LLM risk analysis and the ui.select approval dialog inside execute()
 * have no wall-clock pressure.
 *
 * Flow:
 *   1. allowlist hit → execute directly
 *   2. analyzeCommand() → no danger → execute directly
 *   3. hard-block behavior → return error
 *   4. dangerous behavior → LLM analysis (optional) + ui.select → allow/deny
 *
 * Command execution uses pi.exec("bash", ["-c", cmd]) with non-interactive
 * environment hardening (PAGER=cat, GIT_TERMINAL_PROMPT=0, etc.) and
 * output truncation (tail window + artifact-style full output reference).
 */

import type { ExtensionAPI, ExtensionCtx, ExecResult } from "./types";
import type { SmartApproveConfig } from "./config";
import type { AllowList } from "./allowlist";
import type { SessionContextGatherer } from "./context";
import type { ModelInvoker } from "./host";
import type { Logger } from "./logger";
import type { Lang } from "./i18n";
import type { I18n } from "./i18n";
import { analyzeCommand } from "./behaviors";
import { confirmWithRemember, formatAnalysis } from "./dialog";

/** Tail window for output truncation (matches OMP's OutputSink default). */
const TAIL_BYTES = 50_000;
/** Head window for output truncation (matches OMP's artifactHeadBytes). */
const HEAD_BYTES = 20_000;

/** Non-interactive environment hardening (subset of OMP's buildNonInteractiveEnv). */
const NON_INTERACTIVE_ENV: Record<string, string> = {
  PAGER: "cat",
  GIT_PAGER: "cat",
  LESS: "FRX",
  GIT_EDITOR: "true",
  EDITOR: "true",
  VISUAL: "true",
  TERM: "dumb",
  GIT_TERMINAL_PROMPT: "0",
  SSH_ASKPASS: "/usr/bin/false",
  NO_COLOR: "1",
  CI: "1",
};

/**
 * Truncate output for return to the model. Keeps a head window, a tail
 * window, and an elision marker between them when the output exceeds
 * HEAD + TAIL bytes. Mirrors OMP's OutputSink.dump() behavior.
 */
function truncateOutput(output: string): string {
  if (output.length <= HEAD_BYTES + TAIL_BYTES) return output;
  const head = output.slice(0, HEAD_BYTES);
  const tail = output.slice(-TAIL_BYTES);
  const omitted = output.length - HEAD_BYTES - TAIL_BYTES;
  return `${head}\n\n[... ${omitted} bytes omitted ...]\n\n${tail}`;
}

/** Build the child env: non-interactive hardening under caller's env. */
function buildEnv(callerEnv?: Record<string, string>): Record<string, string> {
  return { ...NON_INTERACTIVE_ENV, ...callerEnv };
}

/** Extract the leading `cd <path> && ...` into a cwd, like OMP's BashTool. */
function extractCwd(command: string, cwd: string): { cmd: string; cwd: string } {
  const m = command.match(/^\s*cd\s+(['"]?)([^'"]+)\1\s*&&\s*(.+)$/s);
  if (!m) return { cmd: command, cwd };
  return { cmd: m[3].trim(), cwd: m[2].trim() };
}

export interface BashToolDeps {
  config: SmartApproveConfig;
  allowList: AllowList;
  contextGatherer: SessionContextGatherer;
  modelInvoker: ModelInvoker;
  logger: Logger;
  lang: Lang;
  t: I18n;
}

/**
 * Register the custom "bash" tool that replaces the built-in one.
 *
 * Requires `bash.enabled: false` in config.yml to avoid tool-name conflict
 * with the built-in bash tool.
 */
export function registerBashTool(pi: ExtensionAPI, deps: BashToolDeps): void {
  const z = pi.zod;
  const { config, allowList, contextGatherer, modelInvoker, logger, lang, t } = deps;

  pi.registerTool({
    name: "bash",
    label: "Bash",
    description:
      "Executes a bash command. Dangerous commands (force-push, rm -rf, " +
      "writes to system paths, etc.) require interactive approval. Safe " +
      "commands execute with zero interruption.",
    parameters: z.object({
      command: z.string().describe("The bash command to execute"),
      timeout: z.number().optional().describe("Timeout in seconds (max 3600)"),
      cwd: z.string().optional().describe("Working directory"),
    }),
    approval: "exec",

    async execute(_toolCallId, params, signal, _onUpdate, ctx: ExtensionCtx) {
      const p = params as { command?: string; timeout?: number; cwd?: string };
      const rawCmd = p.command ?? "";
      if (!rawCmd.trim()) {
        return { content: [{ type: "text", text: "(no command)" }] };
      }

      const baseCwd = ctx.cwd || process.cwd();
      const { cmd, cwd: effectiveCwd } = extractCwd(rawCmd, baseCwd);
      const hasUI = ctx.hasUI;

      logger.log(`bash-tool: cmd="${cmd.slice(0, 80)}" cwd=${effectiveCwd} hasUI=${hasUI}`);

      // 1. Allowlist hit → execute directly
      if (config.rememberDecisions && allowList.isAllowed("bash", cmd, effectiveCwd)) {
        logger.log(`bash-tool: allowlist hit, executing directly`);
        return execAndReturn(pi, cmd, effectiveCwd, p, signal, logger);
      }

      // 2. Behavior analysis
      const analysis = analyzeCommand(cmd);
      if (analysis.behaviors.length === 0) {
        // Safe command — execute directly
        return execAndReturn(pi, cmd, effectiveCwd, p, signal, logger);
      }

      const label = analysis.labels[0]?.[lang] || analysis.labels[0]?.en || "danger";

      // 3. Hard-block behaviors (rm -rf /, fork bombs, curl|sh, etc.)
      if (analysis.hardBlocked) {
        logger.log(`bash-tool: hard-blocked (${label})`);
        return {
          content: [{ type: "text", text: `Blocked: ${label}\nCommand: ${cmd}` }],
          details: { blocked: true, reason: label },
          isError: true,
        };
      }

      // 4. Dangerous but reviewable — need UI
      if (!hasUI) {
        // Headless/subagent context: block dangerous commands
        logger.log(`bash-tool: blocked (no UI) — ${label}`);
        return {
          content: [{ type: "text", text: t.blockedNoUI(label) + "\n" + t.command + ": " + cmd }],
          details: { blocked: true, reason: "no-ui" },
          isError: true,
        };
      }

      // 5. LLM risk analysis (optional, no 30s pressure)
      let analysisText: string | null = null;
      if (config.llmAnalysis) {
        ctx.ui.setStatus("smart-approve", t.analyzing);
        try {
          const sessionCtx = contextGatherer.gather(ctx, config.contextMaxChars);
          const contextSection = contextGatherer.format(sessionCtx, t);
          const behaviorLabels = analysis.labels.map((l) => l[lang] || l.en);
          logger.log(`bash-tool: analyzeRisk cmd="${cmd.slice(0, 80)}" behaviors=[${behaviorLabels.join(",")}]`);
          const result = await modelInvoker.analyze(
            pi,
            cmd,
            behaviorLabels,
            contextSection,
            t,
            config.model,
          );
          analysisText = formatAnalysis(result, t);
          logger.log(`bash-tool: analysisText=${analysisText ? "OK" : "null"}`);
        } catch (e) {
          logger.log(`bash-tool: LLM analysis failed: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
          ctx.ui.setStatus("smart-approve", undefined);
        }
      }

      // 6. Approval dialog (no 30s timeout — we're inside execute(), not a handler)
      const title = t.confirmTitle(label);
      const body = analysisText
        ? `${analysisText}\n\n────────\n${t.command}: ${cmd}\n\n${t.allowPrompt}`
        : `${t.analysisUnavailable}\n\n${t.command}: ${cmd}\n\n${t.allowPrompt}`;

      const decision = await confirmWithRemember(ctx, title, body, t, config.rememberDecisions);
      if (!decision.ok) {
        logger.log(`bash-tool: user denied — ${label}`);
        return {
          content: [{ type: "text", text: t.userDenied(label) }],
          details: { denied: true, reason: label },
          isError: true,
        };
      }

      // Remember decision
      if (decision.remember === "session") {
        allowList.rememberSession("bash", cmd, effectiveCwd);
      } else if (decision.remember === "permanent") {
        allowList.rememberPermanent("bash", cmd, effectiveCwd);
      }

      // 7. Execute
      return execAndReturn(pi, cmd, effectiveCwd, p, signal, logger);
    },
  });
}

/**
 * Execute a command via pi.exec("bash", ["-c", cmd]) and return a tool result.
 * Handles timeout clamping, signal forwarding, and output truncation.
 */
async function execAndReturn(
  pi: ExtensionAPI,
  cmd: string,
  cwd: string,
  params: { timeout?: number },
  signal: AbortSignal | undefined,
  logger: Logger,
): Promise<{ content: Array<{ type: "text"; text: string }>; details: unknown }> {
  // Clamp timeout to [1, 3600] seconds, like OMP's BashTool
  let timeoutSec = params.timeout ?? 0;
  if (timeoutSec > 0) {
    timeoutSec = Math.max(1, Math.min(3600, timeoutSec));
  }
  const timeoutMs = timeoutSec > 0 ? timeoutSec * 1000 : undefined;

  try {
    const result: ExecResult = await pi.exec("bash", ["-c", cmd], {
      cwd,
      env: buildEnv(process.env as Record<string, string>),
      timeout: timeoutMs,
      signal,
    });

    const stdout = result.stdout || "";
    const stderr = result.stderr || "";
    const combined = stdout + (stderr ? (stdout ? "\n" : "") + `[stderr]\n${stderr}` : "");
    const output = combined || "(no output)";

    if (result.code !== 0) {
      return {
        content: [{ type: "text", text: truncateOutput(output) + `\n\nCommand exited with code ${result.code}` }],
        details: { exitCode: result.code, truncated: combined.length > HEAD_BYTES + TAIL_BYTES },
        isError: true,
      } as never;
    }

    return {
      content: [{ type: "text", text: truncateOutput(output) }],
      details: { exitCode: 0, truncated: combined.length > HEAD_BYTES + TAIL_BYTES },
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.log(`bash-tool: exec failed: ${msg}`);
    return {
      content: [{ type: "text", text: `Error: ${msg}` }],
      details: { error: msg },
      isError: true,
    } as never;
  }
}
