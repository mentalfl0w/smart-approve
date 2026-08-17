/**
 * ToolGate template-method branch matrix, exercised through the real
 * BashToolGate and EvalToolGate classes with stubbed collaborators.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { ExtensionCtx, AgentToolResult, RiskAnalysis } from "./types.ts";
import { getI18n } from "./i18n.ts";
import type { Lang } from "./i18n.ts";
import { AutoDecisionPolicy } from "./policy.ts";
import type { SmartApproveConfig } from "./config.ts";
import { BashToolGate } from "./bash-tool.ts";
import { EvalToolGate } from "./eval-tool.ts";
import type { GateDeps, ToolGate } from "./gate.ts";

function makeConfig(overrides: Partial<SmartApproveConfig> = {}): SmartApproveConfig {
  return {
    enabled: true,
    mode: "interactive",
    autoBlockRisk: "high",
    autoFallback: "regex",
    autoInHeadless: false,
    coverage: { eval: true },
    protectedPaths: [],
    llmAnalysis: true,
    rememberDecisions: true,
    contextMaxChars: 3000,
    analysisTimeoutMs: 30_000,
    rpcIdleTimeoutMs: 600_000,
    model: "@tiny",
    ...overrides,
  };
}

interface Calls {
  delegate: number;
  analyze: number;
  notify: string[];
  session: string[];
  permanent: string[];
}

interface Harness {
  deps: GateDeps;
  ctx: ExtensionCtx;
  calls: Calls;
  confirmResult: boolean;
  selectResult: string | number | undefined;
  selectChoices: string[][] | null;
}

interface HarnessOptions {
  hasUI?: boolean;
  isAllowed?: boolean;
  analyzeResult?: RiskAnalysis | null;
}

function makeHarness(
  configOverrides: Partial<SmartApproveConfig> = {},
  opts: HarnessOptions = {},
): Harness {
  const config = makeConfig(configOverrides);
  const calls: Calls = { delegate: 0, analyze: 0, notify: [], session: [], permanent: [] };
  const harness: Harness = {
    deps: {
      config,
      allowList: {
        isAllowed: () => opts.isAllowed ?? false,
        rememberSession: (tool: string, key: string, cwd: string) => {
          calls.session.push(`${tool}:${key}:${cwd}`);
        },
        rememberPermanent: (tool: string, key: string, cwd: string) => {
          calls.permanent.push(`${tool}:${key}:${cwd}`);
        },
      },
      contextGatherer: {
        gather: () => ({ firstUser: null, recentAssistant: [] }),
        format: () => "",
      },
      modelInvoker: {
        analyze: async (): Promise<RiskAnalysis | null> => {
          calls.analyze += 1;
          return opts.analyzeResult === undefined
            ? { risk: "low", recommend: "allow" }
            : opts.analyzeResult;
        },
      },
      policy: new AutoDecisionPolicy(config),
      logger: { log: () => undefined },
      lang: "en" as Lang,
      t: getI18n("en"),
    },
    ctx: {
      hasUI: opts.hasUI ?? true,
      cwd: "/work/project",
      ui: {
        confirm: async () => harness.confirmResult,
        select: async (_title: string, choices: string[]) => {
          harness.selectChoices = [choices];
          return harness.selectResult;
        },
        setStatus: () => undefined,
        notify: (msg: string) => {
          calls.notify.push(msg);
        },
      },
      invokeTool: async () => {
        calls.delegate += 1;
        return { content: [{ type: "text", text: "native-run" }] };
      },
    },
    calls,
    confirmResult: true,
    selectResult: undefined,
    selectChoices: null,
  };
  return harness;
}

function run(
  gate: new (deps: GateDeps) => ToolGate,
  h: Harness,
  params: unknown,
  signal?: AbortSignal,
): Promise<AgentToolResult> {
  return new gate(h.deps).execute(params, signal, undefined, h.ctx);
}

function blockedLabel(r: AgentToolResult): string {
  const m = r.content[0].text.match(/^Blocked: (.+)\n/);
  assert.ok(m, `no Blocked label in: ${r.content[0].text}`);
  return m[1];
}

// ── BashToolGate ─────────────────────────────────────────────────────

test("bash: safe command delegates with zero analysis", async () => {
  const h = makeHarness();
  const r = await run(BashToolGate, h, { command: "ls -la" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.analyze, 0);
});

test("bash: empty command returns (no command) without delegating", async () => {
  const h = makeHarness();
  const r = await run(BashToolGate, h, { command: "   " });
  assert.equal(r.content[0].text, "(no command)");
  assert.equal(h.calls.delegate, 0);
});

test("bash: hard-block wins over everything", async () => {
  const h = makeHarness({}, { isAllowed: true });
  const r = await run(BashToolGate, h, { command: "rm -rf /" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: blockedLabel(r) });
  assert.equal(h.calls.delegate, 0);
  assert.equal(h.calls.analyze, 0);
});

test("bash: allowlist hit delegates without dialog", async () => {
  const h = makeHarness({}, { isAllowed: true });
  const r = await run(BashToolGate, h, { command: "git push -f origin main" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.selectChoices, null);
});

test("bash: headless interactive blocks dangerous commands", async () => {
  const h = makeHarness({}, { hasUI: false });
  const r = await run(BashToolGate, h, { command: "git push -f" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: "no-ui" });
  assert.equal(h.calls.delegate, 0);
});

test("bash: interactive deny blocks", async () => {
  const h = makeHarness();
  h.confirmResult = false;
  const r = await run(BashToolGate, h, { command: "git push -f" });
  assert.equal(r.isError, true);
  assert.equal((r.details as { reason: string }).reason, "git force / mirror push");
  assert.equal(h.calls.delegate, 0);
});

test("bash: interactive select session-allow remembers session", async () => {
  const h = makeHarness();
  h.selectResult = "Allow for this session";
  const r = await run(BashToolGate, h, { command: "git push -f" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.session.length, 1);
  assert.match(h.calls.session[0], /^bash:git push -f:/);
});

test("bash: auto mode AI allow delegates and notifies", async () => {
  const h = makeHarness({ mode: "auto" });
  const r = await run(BashToolGate, h, { command: "git push -f origin feature" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.analyze, 1);
  assert.equal(h.calls.notify.length, 1);
  assert.match(h.calls.notify[0], /Auto-allowed/);
});

test("bash: auto mode AI block returns auto-blocked", async () => {
  const h = makeHarness({ mode: "auto" }, { analyzeResult: { risk: "high", recommend: "allow" } });
  const r = await run(BashToolGate, h, { command: "git push -f" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: "auto" });
  assert.equal(h.calls.delegate, 0);
  assert.equal(h.calls.notify.length, 1);
  assert.match(h.calls.notify[0], /Auto-blocked/);
});

test("bash: auto fallback regex blocks deny-tier (rm -rf ~)", async () => {
  const h = makeHarness({ mode: "auto" }, { analyzeResult: null });
  const r = await run(BashToolGate, h, { command: "rm -rf ~" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: "auto" });
  assert.equal(h.calls.delegate, 0);
});

test("bash: auto fallback regex allows review-tier when AI absent", async () => {
  const h = makeHarness({ mode: "auto" }, { analyzeResult: null });
  const r = await run(BashToolGate, h, { command: "git push -f origin feature" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
});

test("bash: auto fallback block blocks review-tier when AI absent", async () => {
  const h = makeHarness({ mode: "auto", autoFallback: "block" }, { analyzeResult: null });
  const r = await run(BashToolGate, h, { command: "git push -f origin feature" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: "auto" });
});

test("bash: git force push to main is deny-tier", async () => {
  const h = makeHarness({ mode: "auto" }, { analyzeResult: null });
  const r = await run(BashToolGate, h, { command: "git push --force origin main" });
  assert.equal(r.isError, true);
  assert.deepEqual(r.details, { blocked: true, reason: "auto" });
});

test("bash: abort after analysis returns aborted, no dialog", async () => {
  const h = makeHarness();
  const r = await run(BashToolGate, h, { command: "git push -f" }, AbortSignal.abort());
  assert.equal(r.content[0].text, "(aborted)");
  assert.deepEqual(r.details, { aborted: true });
  assert.equal(h.calls.delegate, 0);
  assert.equal(h.selectChoices, null);
});

// ── EvalToolGate ─────────────────────────────────────────────────────

test("eval: safe code delegates directly", async () => {
  const h = makeHarness();
  const r = await run(EvalToolGate, h, { language: "js", code: "const x = 1 + 1" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.analyze, 0);
});

test("eval: subprocess + dangerous payload hard-blocks", async () => {
  const h = makeHarness();
  const r = await run(EvalToolGate, h, { language: "js", code: 'await Bun.$`rm -rf /`' });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /^Blocked:/);
  assert.equal(h.calls.delegate, 0);
  assert.equal(h.calls.analyze, 0);
});

test("eval: subprocess code asks via two-choice dialog", async () => {
  const h = makeHarness();
  h.selectResult = "Allow for this session";
  const r = await run(EvalToolGate, h, {
    language: "py",
    code: "import subprocess\nsubprocess.run(['ls'])",
  });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.ok(h.selectChoices, "select was not used");
  assert.equal(h.selectChoices[0].length, 2);
});

test("eval: auto mode AI-allow delegates subprocess code", async () => {
  const h = makeHarness({ mode: "auto" });
  const r = await run(EvalToolGate, h, { language: "js", code: "Bun.spawn(['ls'])" });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.calls.analyze, 1);
});
