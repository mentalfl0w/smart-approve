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
 *   1. allowlist hit → delegate to native bash tool
 *   2. analyzeCommand() → no danger → delegate to native bash tool
 *   3. hard-block behavior → return error
 *   4. dangerous behavior → LLM analysis (optional) + ui.select → allow/deny
 *
 * Execution is delegated to the native bash tool via ctx.invokeTool().
 * This avoids reimplementing shell path resolution, output truncation,
 * env hardening, and PTY — the native tool handles all of it.
 *
 * No special config needed — the custom tool with the same name "bash" shadows
 * the built-in one via name collision, and ctx.invokeTool delegates execution
 * to the native implementation behind the scenes.
 */

import type { ExtensionAPI, ExtensionCtx } from "./types";
import type { SmartApproveConfig } from "./config";
import type { AllowList } from "./allowlist";
import type { SessionContextGatherer } from "./context";
import type { ModelInvoker } from "./host";
import type { Logger } from "./logger";
import type { Lang } from "./i18n";
import type { I18n } from "./i18n";
import { analyzeCommand } from "./behaviors";
import { confirmWithRemember, formatAnalysis } from "./dialog";

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

    async execute(_toolCallId, params, signal, onUpdate, ctx: ExtensionCtx) {
      const p = params as { command?: string; timeout?: number; cwd?: string };
      const rawCmd = p.command ?? "";
      if (!rawCmd.trim()) {
        return { content: [{ type: "text", text: "(no command)" }] };
      }

      // extractCwd is only for analysis (allowlist key, behavior detection).
      // Execution delegates the RAW command so the native bash tool does
      // its own cd extraction, cwd resolution, and path validation.
      const baseCwd = ctx.cwd || process.cwd();
      const { cmd, cwd: extractedCwd } = extractCwd(rawCmd, baseCwd);
      // Analysis cwd must match the real execution cwd: the cd-prefix path
      // when one is present, else the explicit cwd param, else session cwd.
      const effectiveCwd = extractedCwd !== baseCwd ? extractedCwd : p.cwd ?? baseCwd;
      const hasUI = ctx.hasUI;

      logger.log(`bash-tool: cmd="${cmd.slice(0, 80)}" cwd=${effectiveCwd} hasUI=${hasUI}`);

      // Build params for native bash tool delegation
      const nativeParams: Record<string, unknown> = { command: rawCmd };
      if (p.cwd) nativeParams.cwd = p.cwd;
      if (p.timeout) nativeParams.timeout = p.timeout;

      // Delegate execution to the native bash tool via ctx.invokeTool.
      // This avoids reimplementing shell path resolution, env hardening,
      // output truncation, and PTY — the native tool handles all of it.
      // invokeTool is only present when a native built-in of the same name
      // exists; guard for hosts (e.g. older pi-agent) that lack it.
      const delegate = () => {
        if (!ctx.invokeTool) {
          logger.log("bash-tool: ctx.invokeTool unavailable — cannot delegate");
          return {
            content: [{ type: "text", text: "Error: native bash tool delegation unavailable in this host" }],
            details: { error: "invokeTool-unavailable" },
            isError: true,
          } as never;
        }
        return ctx.invokeTool(nativeParams, { signal, onUpdate });
      };

      // 1. Behavior analysis FIRST — hard-block must win over allowlist
      //    (allowlist entries can predate a rule upgrade, or be hand-edited).
      const analysis = analyzeCommand(cmd);
      const label = analysis.labels[0]?.[lang] || analysis.labels[0]?.en || "danger";

      // 2. Hard-block behaviors (rm -rf /, fork bombs, curl|sh, etc.) —
      //    no allowlist override, no dialog, no LLM review.
      if (analysis.hardBlocked) {
        logger.log(`bash-tool: hard-blocked (${label})`);
        return {
          content: [{ type: "text", text: `Blocked: ${label}\nCommand: ${cmd}` }],
          details: { blocked: true, reason: label },
          isError: true,
        };
      }

      // 3. Allowlist hit → delegate directly
      if (config.rememberDecisions && allowList.isAllowed("bash", cmd, effectiveCwd)) {
        logger.log(`bash-tool: allowlist hit, delegating to native`);
        return delegate();
      }

      // 4. No dangerous behavior — delegate directly
      if (analysis.behaviors.length === 0) {
        return delegate();
      }

      // 5. Dangerous but reviewable — need UI
      if (!hasUI) {
        logger.log(`bash-tool: blocked (no UI) — ${label}`);
        return {
          content: [{ type: "text", text: t.blockedNoUI(label) + "\n" + t.command + ": " + cmd }],
          details: { blocked: true, reason: "no-ui" },
          isError: true,
        };
      }

      // 6. LLM risk analysis (optional, no 30s pressure)
      let analysisText: string | null = null;
      if (config.llmAnalysis) {
        ctx.ui.setStatus("smart-approve", t.analyzing);
        try {
          const sessionCtx = contextGatherer.gather(ctx, config.contextMaxChars);
          const contextSection = contextGatherer.format(sessionCtx, t);
          const behaviorLabels = analysis.labels.map((l) => l[lang] || l.en);
          logger.log(`bash-tool: analyzeRisk cmd="${cmd.slice(0, 80)}" behaviors=[${behaviorLabels.join(",")}]`);
          const result = await modelInvoker.analyze(
            cmd, behaviorLabels, contextSection, t, config.model, signal,
          );
          analysisText = formatAnalysis(result, t);
          logger.log(`bash-tool: analysisText=${analysisText ? "OK" : "null"}`);
        } catch (e) {
          logger.log(`bash-tool: LLM analysis failed: ${e instanceof Error ? e.message : String(e)}`);
        } finally {
          ctx.ui.setStatus("smart-approve", undefined);
        }
      }

      // 6b. Interrupted while analyzing → abort, do not show the dialog.
      if (signal?.aborted) {
        logger.log("bash-tool: aborted during analysis");
        return {
          content: [{ type: "text", text: "(aborted)" }],
          details: { aborted: true },
        };
      }

      // 7. Approval dialog (no 30s timeout — inside execute(), not a handler)
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

      // 7b. Interrupted after approval → do not execute.
      if (signal?.aborted) {
        logger.log("bash-tool: aborted after approval, not executing");
        return {
          content: [{ type: "text", text: "(aborted)" }],
          details: { aborted: true },
        };
      }

      // 8. Execute — delegate to native bash tool
      logger.log(`bash-tool: user approved, delegating to native`);
      return delegate();
    },
  });
}