import assert from "node:assert/strict";
import { test } from "node:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import smartApprove from "./index.ts";
import type { AgentToolResult, ExtensionAPI, ExtensionCtx, HostToolInfo, ToolDefinition } from "./types.ts";

interface TestCallEvent {
  toolName: string;
  input: Record<string, unknown>;
}

interface TestHookResult {
  block?: boolean;
  reason?: string;
  input?: Record<string, unknown>;
}

type TestHandler = (event: unknown, ctx: unknown) => Promise<unknown>;

interface HostHarness {
  api: ExtensionAPI;
  registered: ToolDefinition[];
  handlers: Map<string, TestHandler[]>;
  commands: Map<string, { handler: (args: unknown, ctx: ExtensionCtx) => void | Promise<void> }>;
  delegated: Record<string, unknown>[];
  notices: string[];
  initialize: (ctx: ExtensionCtx) => Promise<void>;
}

type OmpCallResult =
  | { kind: "ready"; input: Record<string, unknown> }
  | { kind: "blocked"; reason: string };

function isTestCallEvent(value: unknown): value is TestCallEvent {
  return value !== null &&
    typeof value === "object" &&
    "toolName" in value &&
    typeof value.toolName === "string" &&
    "input" in value &&
    value.input !== null &&
    typeof value.input === "object" &&
    !Array.isArray(value.input);
}

function isTestHookResult(value: unknown): value is TestHookResult {
  if (value === null || typeof value !== "object") return false;
  if ("block" in value && value.block !== undefined && typeof value.block !== "boolean") return false;
  if ("reason" in value && value.reason !== undefined && typeof value.reason !== "string") return false;
  if (
    "input" in value &&
    value.input !== undefined &&
    (value.input === null || typeof value.input !== "object" || Array.isArray(value.input))
  ) {
    return false;
  }
  return true;
}

function isBlocked(value: unknown): value is { block: true; reason: string } {
  return value !== null &&
    typeof value === "object" &&
    "block" in value &&
    value.block === true &&
    "reason" in value &&
    typeof value.reason === "string";
}

function makeContext(
  delegated: Record<string, unknown>[],
  notices: string[],
  hasUI = false,
  sessionId: string | null = "test-session",
  cwd = "/work/project",
): ExtensionCtx {
  const resolvedSessionId = sessionId ?? undefined;
  const context = {
    hasUI,
    cwd,
    signal: undefined,
    sessionManager: resolvedSessionId === undefined
      ? undefined
      : { getSessionId: () => resolvedSessionId },
    ui: {
      confirm: async () => false,
      select: async (_title: string, choices: string[]) => choices[0],
      setStatus: () => undefined,
      notify: (message: string) => notices.push(message),
    },
    invokeTool: async (params: Record<string, unknown>) => {
      delegated.push(params);
      const serviceName = params.name;
      return {
        content: [{ type: "text", text: "native result" }],
        details: typeof serviceName === "string"
          ? { service: { name: serviceName, state: "running" } }
          : { native: true },
      } as AgentToolResult;
    },
  };
  // This object is a structural stand-in for the runtime-created extension context.
  return context as unknown as ExtensionCtx;
}

function makeHost(tools: HostToolInfo[], beforeHandlers: TestHandler[] = []): HostHarness {
  const registered: ToolDefinition[] = [];
  const handlers = new Map<string, TestHandler[]>([
    ["tool_call", [...beforeHandlers]],
    ["tool_result", []],
    ["session_start", []],
    ["session_shutdown", []],
  ]);
  const commands = new Map<string, { handler: (args: unknown, ctx: ExtensionCtx) => void | Promise<void> }>();
  const delegated: Record<string, unknown>[] = [];
  const notices: string[] = [];
  let runtimeInitialized = false;
  const field = () => {
    const builder: { optional: () => unknown; describe: (text: string) => unknown } = {
      optional: () => builder,
      describe: (_text) => builder,
    };
    return builder;
  };
  const api = {
    on: (event: string, handler: TestHandler) => {
      const bucket = handlers.get(event) ?? [];
      bucket.push(handler);
      handlers.set(event, bucket);
    },
    registerCommand: (name: string, definition: { handler: (args: unknown, ctx: ExtensionCtx) => void | Promise<void> }) => {
      commands.set(name, definition);
    },
    exec: async () => ({ code: 0, stdout: "", stderr: "" }),
    registerTool: (tool: ToolDefinition) => registered.push(tool),
    getAllTools: () => {
      if (!runtimeInitialized) throw new Error("Extension runtime not initialized");
      return tools;
    },
    zod: {
      object: (value: unknown) => value,
      string: field,
      number: field,
      boolean: field,
      enum: (values: readonly string[]) => ({ values }),
    },
  } as unknown as ExtensionAPI;
  return {
    api,
    registered,
    handlers,
    commands,
    delegated,
    notices,
    initialize: async (ctx) => {
      runtimeInitialized = true;
      for (const handler of handlers.get("session_start") ?? []) await handler({}, ctx);
    },
  };
}

function builtin(name: string, parameters: unknown): HostToolInfo {
  return {
    name,
    description: `Native ${name} instructions`,
    parameters,
    sourceInfo: { source: "builtin" },
  };
}

async function withTemporaryHome(run: (home: string) => Promise<void>): Promise<void> {
  const previous = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-host-test-"));
  process.env.HOME = home;
  fs.mkdirSync(path.join(home, ".omp", "agent"), { recursive: true });
  try {
    await run(home);
  } finally {
    if (previous === undefined) delete process.env.HOME;
    else process.env.HOME = previous;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

async function runOmpToolCallHandlers(
  handlers: TestHandler[],
  toolName: string,
  input: Record<string, unknown>,
  ctx: ExtensionCtx,
): Promise<OmpCallResult> {
  let effectiveInput = input;
  for (const handler of handlers) {
    const result = await handler({ toolName, input }, ctx);
    if (isTestHookResult(result) && result.block) {
      return { kind: "blocked", reason: result.reason ?? "blocked" };
    }
    if (isTestHookResult(result) && result.input !== undefined) effectiveInput = result.input;
  }
  return { kind: "ready", input: effectiveInput };
}

async function runPiToolCallHandlers(
  handlers: TestHandler[],
  event: TestCallEvent,
  ctx: ExtensionCtx,
): Promise<unknown> {
  for (const handler of handlers) {
    const result = await handler(event, ctx);
    if (isBlocked(result)) return result;
  }
  return undefined;
}

test("OMP native wrappers preserve schemas, rewritten Eval input, proc guards, and results", async () => {
  await withTemporaryHome(async (home) => {
    const bashSchema = { native: "bash", fields: ["command", "timeout", "cwd", "pty", "async", "name", "ready"] };
    const evalSchema = { native: "eval", languages: ["py", "js"] };
    const host = makeHost([
      builtin("bash", bashSchema),
      builtin("eval", evalSchema),
      builtin("write", { native: "write" }),
      builtin("edit", { native: "edit" }),
    ]);
    let rewrittenCode = 'await Bun.$`rm -rf /`';
    host.handlers.get("tool_call")!.unshift(async (event) => {
      if (!isTestCallEvent(event) || event.toolName !== "eval") return;
      return { input: { ...event.input, code: rewrittenCode, title: "rewritten" } };
    });

    smartApprove(host.api);
    assert.equal(host.registered.length, 0);
    const ctx = makeContext(host.delegated, host.notices);
    await host.initialize(ctx);
    assert.deepEqual(host.registered.map((tool) => tool.name), ["bash", "eval"]);
    assert.strictEqual(host.registered[0].parameters, bashSchema);
    assert.strictEqual(host.registered[1].parameters, evalSchema);
    assert.match(host.registered[0].description, /Native bash instructions/);
    assert.match(host.registered[1].description, /Native eval instructions/);
    assert.match(host.registered[1].description, /omp-task-group-pool-proc-cancel:v1/);
    assert.doesNotMatch(host.registered[0].description, /omp-task-group-pool-proc-cancel:v1/);
    assert.equal(host.registered.some((tool) => tool.name === "hub"), false);
    const bashTool = host.registered.find((tool) => tool.name === "bash")!;
    const serviceParams = {
      command: "bash",
      name: "smart-approve-shell",
      pty: true,
      ready: { log: "ready" },
    };
    const serviceResult = await bashTool.execute("service", serviceParams, undefined, undefined, ctx);
    assert.equal(serviceResult.content[0].text, "native result");
    assert.deepEqual(host.delegated[0], serviceParams);

    const safeBashParams = { command: "bun run dev", async: true, timeout: 0, pty: false };
    const safeBashResult = await bashTool.execute("background", safeBashParams, undefined, undefined, ctx);
    assert.equal(safeBashResult.content[0].text, "native result");
    assert.deepEqual(host.delegated[1], safeBashParams);

    fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
    fs.symlinkSync(path.join(home, ".aws"), path.join(home, "aws-link"), "dir");
    fs.symlinkSync("/etc", path.join(home, "etc-link"), "dir");

    const callHandler = host.handlers.get("tool_call")!.at(-1)!;
    const dangerousInput = await callHandler(
      { toolName: "write", input: { path: "proc://smart-approve-shell", content: "rm -rf /" } },
      ctx,
    );
    assert.equal(isBlocked(dangerousInput), true);
    const ordinaryInput = await callHandler(
      { toolName: "write", input: { path: "proc://smart-approve-shell", content: "echo ok" } },
      ctx,
    );
    assert.equal(ordinaryInput, undefined);

    // Public proc routing is by project + name; another session targeting the
    // same service must not become an untracked bypass.
    const otherSessionCtx = makeContext(host.delegated, host.notices, false, "other-session");
    const crossSessionDangerous = await callHandler(
      { toolName: "write", input: { path: "proc://smart-approve-shell", content: "rm -rf /" } },
      otherSessionCtx,
    );
    assert.equal(isBlocked(crossSessionDangerous), true);

    const protectedWrite = await callHandler(
      { toolName: "write", input: { path: ".env", content: "secret" } },
      ctx,
    );
    assert.equal(isBlocked(protectedWrite), true);
    const systemWrite = await callHandler(
      { toolName: "write", input: { path: "/etc/passwd", content: "malicious" } },
      ctx,
    );
    assert.equal(isBlocked(systemWrite), true);
    const sudoersDirectoryWrite = await callHandler(
      { toolName: "write", input: { path: "/etc/sudoers.d/agent", content: "malicious" } },
      ctx,
    );
    assert.equal(isBlocked(sudoersDirectoryWrite), true);
    const systemSymlinkParentWrite = await callHandler(
      { toolName: "write", input: { path: path.join(home, "etc-link", "passwd.new"), content: "malicious" } },
      ctx,
    );
    assert.equal(isBlocked(systemSymlinkParentWrite), true);
    const protectedSymlinkParentWrite = await callHandler(
      { toolName: "write", input: { path: path.join(home, "aws-link", "credentials"), content: "secret" } },
      ctx,
    );
    assert.equal(isBlocked(protectedSymlinkParentWrite), true);
    const rawDeviceWrite = await callHandler(
      { toolName: "edit", input: { path: "/dev/nvme0n1", content: "malicious" } },
      ctx,
    );
    assert.equal(isBlocked(rawDeviceWrite), true);

    fs.symlinkSync("/etc/passwd", path.join(home, "passwd-alias"));
    const sensitiveAlias = await callHandler(
      { toolName: "write", input: { path: path.join(home, "passwd-alias"), content: "malicious" } },
      ctx,
    );
    assert.equal(isBlocked(sensitiveAlias), true);
    const protectedPatch = await callHandler(
      {
        toolName: "apply_patch",
        input: { input: "*** Begin Patch\n*** Update File: .env\n@@\n+secret\n*** End Patch" },
      },
      ctx,
    );
    assert.equal(isBlocked(protectedPatch), true);
    const protectedAstEdit = await callHandler(
      { toolName: "ast_edit", input: { paths: [".env"], ops: [{ pat: "old", out: "new" }] } },
      ctx,
    );
    assert.equal(isBlocked(protectedAstEdit), true);

    const protectedRename = await callHandler(
      {
        toolName: "edit",
        input: {
          path: "notes.md",
          edits: [{ op: "update", rename: ".env", diff: "*** Begin Patch\n*** End Patch" }],
        },
      },
      ctx,
    );
    assert.equal(isBlocked(protectedRename), true);

    const hubCall = await callHandler({ toolName: "hub", input: { op: "start" } }, ctx);
    assert.equal(hubCall, undefined);

    const evalTool = host.registered.find((tool) => tool.name === "eval")!;
    const original = { language: "js", code: "1 + 1", timeout: 20, reset: false };
    const rewritten = await runOmpToolCallHandlers(
      host.handlers.get("tool_call")!,
      "eval",
      original,
      ctx,
    );
    if (rewritten.kind === "blocked") throw new Error(rewritten.reason);
    const blockedEval = await evalTool.execute("eval-danger", rewritten.input, undefined, undefined, ctx);
    assert.equal(blockedEval.isError, true);
    assert.equal(host.delegated.length, 2);

    rewrittenCode = "const answer = 42";
    const safeRewrite = await runOmpToolCallHandlers(
      host.handlers.get("tool_call")!,
      "eval",
      original,
      ctx,
    );
    if (safeRewrite.kind === "blocked") throw new Error(safeRewrite.reason);
    const evalResult = await evalTool.execute("eval-safe", safeRewrite.input, undefined, undefined, ctx);
    assert.equal(evalResult.content[0].text, "native result");
    assert.deepEqual(host.delegated[2], {
      language: "js",
      code: "const answer = 42",
      timeout: 20,
      reset: false,
      title: "rewritten",
    });
    assert.equal(host.delegated.length, 3);

    const statusCommand = host.commands.get("smart-approve")!;
    await statusCommand.handler("status", ctx);
    assert.match(host.notices.at(-1) ?? "", /coverage: bash=true eval=true proc-input=tracked protected-paths=true/);
    assert.doesNotMatch(host.notices.at(-1) ?? "", /hub=/i);

    // Session shutdown drops that session's tracked services; a later write
    // must no longer be classified against the dead registration.
    for (const handler of host.handlers.get("session_shutdown") ?? []) await handler({}, ctx);
    const afterShutdown = await callHandler(
      { toolName: "write", input: { path: "proc://smart-approve-shell", content: "rm -rf /" } },
      ctx,
    );
    assert.equal(afterShutdown, undefined);
  });
});

test("Pi uses one pre-execution gate without shadowing native Bash", async () => {
  await withTemporaryHome(async () => {
    let rewriteCommand = "rm -rf /";
    const mutator: TestHandler = async (event) => {
      if (isTestCallEvent(event) && event.toolName === "bash") event.input.command = rewriteCommand;
    };
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("write", { native: "write" }),
      builtin("edit", { native: "edit" }),
    ], [mutator]);
    smartApprove(host.api);
    assert.equal(host.registered.length, 0);
    const ctx = makeContext(host.delegated, host.notices);
    await host.initialize(ctx);
    const handlers = host.handlers.get("tool_call")!;
    const blocked = await runPiToolCallHandlers(handlers, { toolName: "bash", input: { command: "ls" } }, ctx);
    assert.equal(isBlocked(blocked), true);

    rewriteCommand = "echo safe";
    const allowed = await runPiToolCallHandlers(handlers, { toolName: "bash", input: { command: "rm -rf /" } }, ctx);
    assert.equal(allowed, undefined);
    assert.equal(host.delegated.length, 0);
  });
});

test("OMP reports shell-only proc input when Eval coverage is disabled", async () => {
  await withTemporaryHome(async (home) => {
    fs.writeFileSync(
      path.join(home, ".omp", "agent", "smart-approve.json"),
      JSON.stringify({ coverage: { eval: false }, protectedPaths: [] }),
    );
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("eval", { native: "eval" }),
      builtin("write", { native: "write" }),
    ]);
    smartApprove(host.api);
    const ctx = makeContext(host.delegated, host.notices);
    await host.initialize(ctx);
    assert.deepEqual(host.registered.map((tool) => tool.name), ["bash"]);
    await host.commands.get("smart-approve")!.handler("status", ctx);
    assert.match(host.notices.at(-1) ?? "", /coverage: bash=true eval=false proc-input=shell-only protected-paths=true/);
  });
});

test("OMP does not report tracked proc input without a stable session id", async () => {
  await withTemporaryHome(async () => {
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("eval", { native: "eval" }),
      builtin("write", { native: "write" }),
    ]);
    smartApprove(host.api);
    const ctx = makeContext(host.delegated, host.notices, false, null);
    await host.initialize(ctx);
    await host.commands.get("smart-approve")!.handler("status", ctx);
    assert.match(host.notices.at(-1) ?? "", /coverage: bash=true eval=true proc-input=false protected-paths=true/);
  });
});

test("OMP reports shell-only proc input when native wrappers are incomplete", async () => {
  await withTemporaryHome(async () => {
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("write", { native: "write" }),
    ]);
    smartApprove(host.api);
    const ctx = makeContext(host.delegated, host.notices);
    await host.initialize(ctx);
    await host.commands.get("smart-approve")!.handler("status", ctx);
    assert.match(host.notices.at(-1) ?? "", /coverage: bash=true eval=false proc-input=shell-only protected-paths=true/);
  });
});

test("OMP tracks proc cwd changes so later relative protected writes are gated", async () => {
  await withTemporaryHome(async () => {
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("eval", { native: "eval" }),
      builtin("write", { native: "write" }),
    ]);
    smartApprove(host.api);
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-proc-cwd-"));
    const awsDir = path.join(workspace, ".aws");
    fs.mkdirSync(awsDir);
    const ctx = makeContext(host.delegated, host.notices, false, "test-session", workspace);
    await host.initialize(ctx);

    const bashTool = host.registered.find((tool) => tool.name === "bash")!;
    const toolCall = host.handlers.get("tool_call")!.at(-1)!;
    const toolResult = host.handlers.get("tool_result")!.at(-1)!;

    await bashTool.execute(
      "shell",
      { command: "bash", name: "shell-cwd", pty: true },
      undefined,
      undefined,
      ctx,
    );
    const shellChange = "ln -s /etc link && cd link";
    // The missing `link` target is confirmation-worthy at gate time; simulate
    // an approved execution that creates the symlink and changes cwd.
    fs.symlinkSync("/etc", path.join(workspace, "link"), "dir");
    await toolResult(
      {
        toolName: "write",
        input: { path: "proc://shell-cwd", content: shellChange },
        isError: false,
      },
      ctx,
    );
    const shellBlocked = await toolCall(
      { toolName: "write", input: { path: "proc://shell-cwd", content: "cat passwd" } },
      ctx,
    );
    assert.equal(isBlocked(shellBlocked), true);

    await bashTool.execute(
      "dynamic-shell",
      { command: "bash", name: "dynamic-shell", pty: true },
      undefined,
      undefined,
      ctx,
    );
    await toolResult(
      {
        toolName: "write",
        input: { path: "proc://dynamic-shell", content: 'cd "$WORKING_DIR"' },
        isError: false,
      },
      ctx,
    );
    const unresolvedCwdBlocked = await toolCall(
      { toolName: "write", input: { path: "proc://dynamic-shell", content: "echo ok" } },
      ctx,
    );
    assert.equal(isBlocked(unresolvedCwdBlocked), true);

    await bashTool.execute(
      "chain-shell",
      { command: "bash", name: "chain-shell", pty: true },
      undefined,
      undefined,
      ctx,
    );
    const canonicalWorkspace = fs.realpathSync(workspace);
    const upToRoot = path.relative(canonicalWorkspace, "/") || ".";
    const chainBlocked = await toolCall(
      {
        toolName: "write",
        input: {
          path: "proc://chain-shell",
          content: `true && cd ${upToRoot} && cd etc && touch marker`,
        },
      },
      ctx,
    );
    if (!isBlocked(chainBlocked)) assert.fail("expected chained cd to reach a sensitive directory");

    const missingThenAbsolute = await toolCall(
      {
        toolName: "write",
        input: {
          path: "proc://chain-shell",
          content: "cd missing; cd /etc; touch marker",
        },
      },
      ctx,
    );
    if (!isBlocked(missingThenAbsolute)) {
      assert.fail("expected absolute cd after a missing target to be checked");
    }

    await bashTool.execute(
      "python",
      { command: "python3", name: "python-cwd", pty: true },
      undefined,
      undefined,
      ctx,
    );
    const chdirCode = `import os\nos.chdir(${JSON.stringify(awsDir)})`;
    assert.equal(
      await toolCall(
        { toolName: "write", input: { path: "proc://python-cwd", content: chdirCode } },
        ctx,
      ),
      undefined,
    );
    await toolResult(
      {
        toolName: "write",
        input: { path: "proc://python-cwd", content: chdirCode },
        isError: false,
      },
      ctx,
    );
    const pythonBlocked = await toolCall(
      {
        toolName: "write",
        input: { path: "proc://python-cwd", content: "open('credentials', 'w')" },
      },
      ctx,
    );
    assert.equal(isBlocked(pythonBlocked), true);

    for (const handler of host.handlers.get("session_shutdown") ?? []) await handler({}, ctx);
    fs.rmSync(workspace, { recursive: true, force: true });
  });
});

test("OMP retains detached service classification after owner-session shutdown", async () => {
  await withTemporaryHome(async () => {
    const host = makeHost([
      builtin("bash", { native: "bash" }),
      builtin("eval", { native: "eval" }),
      builtin("write", { native: "write" }),
    ]);
    smartApprove(host.api);
    const owner = makeContext(host.delegated, host.notices, false, "owner-session");
    await host.initialize(owner);

    const bashTool = host.registered.find((tool) => tool.name === "bash")!;
    const serviceParams = { command: "bash", name: "detached-shell", pty: true };
    const serviceResult = await bashTool.execute("service", serviceParams, undefined, undefined, owner);
    assert.equal(serviceResult.content[0].text, "native result");

    const toolCall = host.handlers.get("tool_call")!.at(-1)!;
    const toolResult = host.handlers.get("tool_result")!.at(-1)!;
    const dangerousWrite = (ctx: ExtensionCtx) => toolCall(
      { toolName: "write", input: { path: "proc://detached-shell", content: "rm -rf /" } },
      ctx,
    );

    assert.equal(isBlocked(await dangerousWrite(owner)), true);
    await toolResult(
      {
        toolName: "write",
        input: { path: "proc://detached-shell/mode", content: "detached" },
        isError: false,
      },
      owner,
    );

    for (const handler of host.handlers.get("session_shutdown") ?? []) await handler({}, owner);
    const other = makeContext(host.delegated, host.notices, false, "other-session");
    assert.equal(isBlocked(await dangerousWrite(other)), true);

    // Returning it to session lifetime lets the writing session clean it up.
    await toolResult(
      {
        toolName: "write",
        input: { path: "proc://detached-shell/mode", content: "session" },
        isError: false,
      },
      other,
    );
    for (const handler of host.handlers.get("session_shutdown") ?? []) await handler({}, other);
    assert.equal(await dangerousWrite(other), undefined);
  });
});
