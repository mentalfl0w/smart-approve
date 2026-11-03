/**
 * ToolGate template-method branch matrix, exercised through the real
 * BashToolGate and EvalToolGate classes with stubbed collaborators.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { ExtensionCtx, AgentToolResult, RiskAnalysis } from "./types.ts";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getI18n } from "./i18n.ts";
import type { Lang } from "./i18n.ts";
import { AutoDecisionPolicy } from "./policy.ts";
import type { SmartApproveConfig } from "./config.ts";
import { BashToolGate, UNRESOLVED_CWD } from "./bash-tool.ts";
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
      protectedPathMatcher: {
        isProtected: (filePath: string) => filePath === ".env" || filePath.endsWith("/.env"),
      },
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

function reasonOf(r: AgentToolResult): unknown {
  if (r.details && typeof r.details === "object" && "reason" in r.details) {
    return r.details.reason;
  }
  return undefined;
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

test("bash: tilde cwd expands before sensitive-directory analysis", async () => {
  const h = makeHarness();
  const r = await run(BashToolGate, h, { command: "ls", cwd: "~/.ssh" });
  assert.equal(r.isError, true);
  assert.equal(h.calls.delegate, 0);

  const viaCd = makeHarness();
  const cdResult = await run(BashToolGate, viaCd, { command: "cd ~/.ssh && ls" });
  assert.equal(cdResult.isError, true);
  assert.equal(viaCd.calls.delegate, 0);
});

test("bash: $HOME and ${HOME} cwd forms expand before analysis", async () => {
  for (const cwd of ["$HOME/.ssh", "${HOME}/.ssh"]) {
    const h = makeHarness();
    const r = await run(BashToolGate, h, { command: "ls", cwd });
    assert.equal(r.isError, true, `cwd ${cwd}`);
    assert.equal(h.calls.delegate, 0);
  }

  const viaCd = makeHarness();
  const quoted = await run(BashToolGate, viaCd, { command: 'cd "$HOME/.ssh" && ls' });
  assert.equal(quoted.isError, true);
  assert.equal(viaCd.calls.delegate, 0);
});

test("bash: only the first leading cd target determines the effective cwd", async () => {
  const h = makeHarness();
  const r = await run(BashToolGate, h, { command: "cd /etc && echo safe && touch marker" });
  assert.equal(r.isError, true);
  assert.equal(h.calls.delegate, 0);

  const inside = makeHarness();
  const allowed = await run(BashToolGate, inside, {
    command: "cd / && echo safe && touch marker",
  });
  assert.equal(allowed.content[0].text, "native-run");
  assert.equal(inside.calls.delegate, 1);

  const commented = makeHarness();
  const commentedResult = await run(BashToolGate, commented, {
    command: "# change directory\ncd /etc && echo safe",
  });
  assert.equal(commentedResult.isError, true);
  assert.equal(commented.calls.delegate, 0);
});

test("bash: literal cd segments entering sensitive directories are hard-blocked", async () => {
  for (const command of [
    "cd /etc; touch marker",
    "cd /tmp && cd /etc && touch marker",
    "cd -P /etc && touch marker",
    "cd -LP /etc && touch marker",
    "cd -- /etc && touch marker",
  ]) {
    const h = makeHarness();
    const r = await run(BashToolGate, h, { command });
    assert.equal(r.isError, true, command);
    assert.deepEqual(r.details, { blocked: true, reason: blockedLabel(r) }, command);
    assert.equal(h.calls.analyze, 0, command);
    assert.equal(h.calls.delegate, 0, command);
  }

  // A literal, non-sensitive cd followed by `;` should not demand confirmation.
  const safe = makeHarness();
  const safeResult = await run(BashToolGate, safe, {
    command: "cd /; touch marker",
  });
  assert.equal(safeResult.content[0].text, "native-run");
  assert.equal(safe.calls.delegate, 1);
});

test("bash: escaped HOME is unresolved, while single-quoted HOME stays literal", async () => {
  const literalHomeDir = fs.mkdtempSync(path.join(os.homedir(), ".smart-approve-literal-home-"));
  const literalTarget = path.join(literalHomeDir, "$HOME");
  fs.mkdirSync(literalTarget);
  try {
    const literalHome = makeHarness();
    const literal = await run(BashToolGate, literalHome, {
      command: `cd '${literalTarget}' && echo safe`,
    });
    assert.equal(literal.content[0].text, "native-run");
    assert.equal(literalHome.calls.delegate, 1);
  } finally {
    fs.rmSync(literalHomeDir, { recursive: true, force: true });
  }

  const escapedHome = makeHarness({}, { hasUI: false, isAllowed: true });
  const denied = await run(BashToolGate, escapedHome, {
    command: "cd \\$HOME/.ssh && echo safe",
  });
  assert.equal(denied.isError, true);
  assert.deepEqual(denied.details, { blocked: true, reason: "no-ui" });
  assert.equal(escapedHome.calls.delegate, 0);
});

test("bash: symlinked cwd aliases are canonicalized before sensitivity analysis", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-cwd-link-"));
  const alias = path.join(dir, "etc-link");
  fs.symlinkSync("/etc", alias, "dir");
  try {
    const h = makeHarness();
    const r = await run(BashToolGate, h, { command: "ls", cwd: alias });
    assert.equal(r.isError, true);
    assert.equal(h.calls.delegate, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("bash: unresolved dynamic cwd requires confirmation and headless denies it", async () => {
  const command = 'cd "$WORKING_DIR" && echo safe';
  const interactive = makeHarness();
  const confirmed = await run(BashToolGate, interactive, { command });
  assert.equal(confirmed.isError, true);
  assert.match(confirmed.content[0].text, /cannot be resolved without running the shell/);
  assert.equal(interactive.calls.analyze, 0);
  assert.equal(interactive.calls.delegate, 0);

  // Remembered approvals must not turn an unresolved cwd into a safe path.
  const headless = makeHarness({}, { hasUI: false, isAllowed: true });
  const blocked = await run(BashToolGate, headless, { command });
  assert.equal(blocked.isError, true);
  assert.deepEqual(blocked.details, { blocked: true, reason: "no-ui" });
  assert.equal(headless.calls.delegate, 0);

  const dynamicParam = makeHarness({}, { hasUI: false });
  const denied = await run(BashToolGate, dynamicParam, { command: "ls", cwd: "$WORKING_DIR" });
  assert.equal(denied.isError, true);
  assert.deepEqual(denied.details, { blocked: true, reason: "no-ui" });
  assert.equal(dynamicParam.calls.delegate, 0);
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

test("bash: auto fallback regex blocks deny-tier protected force-push", async () => {
  const h = makeHarness({ mode: "auto" }, { analyzeResult: null });
  const r = await run(BashToolGate, h, { command: "git push --force origin main" });
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

const TASK_GROUP_CANCEL_SOURCE = `
const TG_GROUP = "tgm9x2k4abc";
const TG_PROTOCOL = "omp-task-group/eval-result-v1";
async function tgCancelPool(pool) {
  const result = await tool.write({ path: "proc://" + TG_GROUP + "/kill" });
  const proc = result && result.details && result.details.proc;
  const outcomes = proc && Array.isArray(proc.cancelled) ? proc.cancelled : [];
  const target = outcomes.find((item) => tgPoolIsRecord(item) && item.id === TG_GROUP);
  return { outcomes, target };
}
`;

test("eval: exact Task Group pool-cancel write delegates without review", async () => {
  const h = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const r = await run(EvalToolGate, h, { language: "js", code: TASK_GROUP_CANCEL_SOURCE });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 1);
});

test("eval: Task Group-looking extra properties still require confirmation", async () => {
  const h = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: `
const TG_GROUP = "tgabc";
const TG_PROTOCOL = "omp-task-group/eval-result-v1";
await tool.write({ path: "proc://" + TG_GROUP + "/kill", content: "extra" });
`,
  });
  assert.equal(r.isError, true);
  assert.equal(reasonOf(r), "no-ui");
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 0);
});

test("eval: object write to a protected path still requires confirmation", async () => {
  const h = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: 'await tool.write({ path: ".env" })',
  });
  assert.equal(r.isError, true);
  assert.equal(reasonOf(r), "no-ui");
  assert.equal(h.calls.delegate, 0);
});

test("eval: direct protected write helper requires confirmation even in auto mode", async () => {
  const h = makeHarness({ mode: "auto" });
  h.selectResult = "Allow for this session";
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: 'await write(".env", "secret")',
  });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.selectChoices?.[0].length, 2);
});

test("eval protected writes bypass remembered approvals and require user confirmation", async () => {
  const h = makeHarness({ mode: "auto" }, { isAllowed: true });
  h.selectResult = "Allow for this session";
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: 'await write(".env", "secret")',
  });
  assert.equal(r.content[0].text, "native-run");
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 1);
  assert.equal(h.selectChoices?.[0].length, 2);
});

test("eval computed file-write targets require confirmation in auto mode", async () => {
  const h = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: "await Bun.write(target, content)",
  });
  assert.equal(r.isError, true);
  assert.equal((r.details as { reason: string }).reason, "no-ui");
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 0);
});

test("eval hard-blocks sensitive system-file writes without subprocess intent", async () => {
  const h = makeHarness();
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: 'await write("/etc/sudoers.d/agent", "secret")',
  });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /^Blocked:/);
  assert.equal(h.calls.analyze, 0);
  assert.equal(h.calls.delegate, 0);
});

test("eval hard-blocks symlink aliases of system-sensitive files", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-eval-link-"));
  try {
    const alias = path.join(dir, "passwd");
    fs.symlinkSync("/etc/passwd", alias);
    const h = makeHarness();
    const r = await run(EvalToolGate, h, {
      language: "js",
      code: `await write(${JSON.stringify(alias)}, "secret")`,
    });
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /^Blocked:/);
    assert.equal(h.calls.delegate, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("eval hard-blocks relative writes after changing into a sensitive directory", async () => {
  const h = makeHarness();
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: 'process.chdir("/etc"); await write("passwd", "secret")',
  });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /^Blocked:/);
  assert.equal(h.calls.delegate, 0);
});

test("eval requires confirmation for relative writes after a dynamic directory change", async () => {
  const h = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const r = await run(EvalToolGate, h, {
    language: "js",
    code: "process.chdir(target); await write('output.txt', content)",
  });
  assert.equal(r.isError, true);
  assert.equal((r.details as { reason: string }).reason, "no-ui");
  assert.equal(h.calls.delegate, 0);
});
test("eval gates Python shell magics and writefile targets", async () => {
  const shell = makeHarness();
  const blockedShell = await run(EvalToolGate, shell, {
    language: "py",
    code: "!ssh host",
  });
  assert.equal(blockedShell.isError, true);
  assert.match(blockedShell.content[0].text, /^Blocked:/);
  assert.equal(shell.calls.analyze, 0);
  assert.equal(shell.calls.delegate, 0);

  const protectedWrite = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const blockedWrite = await run(EvalToolGate, protectedWrite, {
    language: "py",
    code: "%%writefile .env\nsecret",
  });
  assert.equal(blockedWrite.isError, true);
  assert.equal((blockedWrite.details as { reason: string }).reason, "no-ui");
  assert.equal(protectedWrite.calls.delegate, 0);

  const systemWrite = makeHarness();
  const blockedSystemWrite = await run(EvalToolGate, systemWrite, {
    language: "py",
    code: "%%writefile /etc/passwd\nsecret",
  });
  assert.equal(blockedSystemWrite.isError, true);
  assert.match(blockedSystemWrite.content[0].text, /^Blocked:/);
  assert.equal(systemWrite.calls.delegate, 0);

  const sensitiveCwd = makeHarness();
  const blockedCwd = await run(EvalToolGate, sensitiveCwd, {
    language: "py",
    code: "%cd /etc",
  });
  assert.equal(blockedCwd.isError, true);
  assert.match(blockedCwd.content[0].text, /^Blocked:/);
  assert.equal(sensitiveCwd.calls.delegate, 0);
});

test("eval external Python source and unresolved proc cwd require confirmation", async () => {
  const externalSource = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const blockedSource = await run(EvalToolGate, externalSource, {
    language: "py",
    code: "%run script.py",
  });
  assert.equal(blockedSource.isError, true);
  assert.equal((blockedSource.details as { reason: string }).reason, "no-ui");
  assert.equal(externalSource.calls.analyze, 0);
  assert.equal(externalSource.calls.delegate, 0);

  const unknownCwdWrite = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const blockedWrite = await run(EvalToolGate, unknownCwdWrite, {
    language: "py",
    code: "open('credentials', 'w')",
    cwd: UNRESOLVED_CWD,
  });
  assert.equal(blockedWrite.isError, true);
  assert.equal((blockedWrite.details as { reason: string }).reason, "no-ui");
  assert.equal(unknownCwdWrite.calls.delegate, 0);

  const unknownCwdSpawn = makeHarness({ mode: "auto", autoInHeadless: true }, { hasUI: false });
  const blockedSpawn = await run(EvalToolGate, unknownCwdSpawn, {
    language: "js",
    code: "Bun.spawn(['ls'])",
    cwd: UNRESOLVED_CWD,
  });
  assert.equal(blockedSpawn.isError, true);
  assert.equal((blockedSpawn.details as { reason: string }).reason, "no-ui");
  assert.equal(unknownCwdSpawn.calls.delegate, 0);
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
