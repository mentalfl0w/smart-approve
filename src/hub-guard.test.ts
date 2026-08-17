import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";

import { HubLaunchGuard } from "./hub-guard.ts";

const SESSION = "/Users/omp/workspace/smart-approve";
const guard = new HubLaunchGuard();

test("non-start ops always pass through", () => {
  // Even with a clearly dangerous payload attached, only op === "start" is
  // reviewed — everything else is the host's business.
  for (const op of ["stop", "restart", "logs", "send", "list", "wait", "cancel"]) {
    const verdict = guard.evaluate(
      { op, application: "sudo", args: ["rm", "-rf", "/"] },
      SESSION,
    );
    assert.deepEqual(verdict, { block: false }, `op ${op} must pass`);
  }
});

test("rule 1: hard-rejected applications are blocked", () => {
  for (const app of ["osascript", "sudo", "ssh", "curl"]) {
    const verdict = guard.evaluate({ op: "start", application: app, args: [] }, SESSION);
    assert.equal(verdict.block, true, `${app} must be blocked`);
    assert.ok(verdict.reason, `${app} must carry a reason`);
    assert.equal(verdict.reason.en, `Blocked hub start: ${app} is not allowed`);
    assert.equal(verdict.reason.zh, `已拦截 hub 启动：不允许的应用 ${app}`);
  }
});

test("rule 2: interpreter with an execution flag is blocked", () => {
  const cases = [
    { application: "sh", args: ["-c", "ls"] },
    { application: "python", args: ["-c", "print(1)"] },
    { application: "bash", args: ["-i"] },
    { application: "node", args: ["--eval", "process.exit(1)"] },
    { application: "bun", args: ["-e", "console.log(1)"] },
  ];
  for (const params of cases) {
    const verdict = guard.evaluate({ op: "start", ...params }, SESSION);
    assert.equal(verdict.block, true, JSON.stringify(params) + " must be blocked");
    assert.ok(verdict.reason);
    assert.equal(verdict.reason.en, "Blocked hub start: interpreter with execution flag");
    assert.equal(verdict.reason.zh, "已拦截 hub 启动：解释器带执行标志");
  }
});

test("rule 2: interpreter without an execution flag passes", () => {
  assert.equal(
    guard.evaluate({ op: "start", application: "bun", args: ["run", "dev"] }, SESSION).block,
    false,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "node", args: ["server.js"] }, SESSION).block,
    false,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "python", args: ["script.py"] }, SESSION).block,
    false,
  );
});

test("rule 2: python-family executables normalize to python", () => {
  for (const app of ["python", "python2", "python3", "pypy", "pypy3", "Python3"]) {
    const verdict = guard.evaluate({ op: "start", application: app, args: ["-c", "print(1)"] }, SESSION);
    assert.equal(verdict.block, true, `${app} -c must be blocked`);
  }
  assert.equal(
    guard.evaluate({ op: "start", application: "python3", args: ["manage.py", "runserver"] }, SESSION).block,
    false,
  );
});

test("rule 3: dangerous payloads in args are blocked", () => {
  const cases = [
    { application: "env", args: ["rm", "-rf", "/"] },
    { application: "env", args: ["rm", "-Rf", "/tmp/x"] },
    { application: "env", args: ["rm", "-r", "-f", "/tmp/x"] },
    { application: "env", args: ["chmod", "-R", "777", "/etc/foo"] },
    { application: "env", args: ["chown", "root:root", "/etc/passwd"] },
    { application: "env", args: ["dd", "if=/dev/zero", "of=/dev/sda"] },
    { application: "env", args: ["mkfs.ext4", "/dev/sdb1"] },
    { application: "systemctl", args: ["shutdown"] },
    { application: "env", args: [":(){ :|:& };:"] },
    { application: "cat", args: ["/etc/shadow"] },
    { application: "echo", args: ["x", ">", "/dev/sda"] },
    { application: "echo", args: ["x", ">", "/dev/nvme0n1"] },
  ];
  for (const params of cases) {
    const verdict = guard.evaluate({ op: "start", ...params }, SESSION);
    assert.equal(verdict.block, true, JSON.stringify(params) + " must be blocked");
    assert.ok(verdict.reason);
    assert.equal(verdict.reason.en, "Blocked hub start: dangerous arguments");
    assert.equal(verdict.reason.zh, "已拦截 hub 启动：参数含危险内容");
  }
});

test("rule 4: sensitive cwd outside the session is blocked", () => {
  const cases = [
    "/etc",
    "/etc/nginx",
    "/usr/local/bin",
    "/var/log",
    "/boot",
    "/Library/LaunchDaemons",
    "/System",
    "/private/etc",
  ];
  for (const cwd of cases) {
    const verdict = guard.evaluate({ op: "start", application: "myapp", args: [], cwd }, SESSION);
    assert.equal(verdict.block, true, `cwd ${cwd} must be blocked`);
    assert.ok(verdict.reason);
    assert.equal(verdict.reason.en, "Blocked hub start: sensitive working directory");
    assert.equal(verdict.reason.zh, "已拦截 hub 启动：敏感工作目录");
  }
});

test("rule 4: tilde and home-relative sensitive dirs are blocked", () => {
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "~/.ssh" }, SESSION).block,
    true,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "~/.gnupg" }, SESSION).block,
    true,
  );
  const expanded = path.join(os.homedir(), ".ssh");
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: expanded }, SESSION).block,
    true,
  );
});

test("rule 4: cwd under the session passes even when sensitive elsewhere", () => {
  const inside = path.join(SESSION, "packages/agent");
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: inside }, SESSION).block,
    false,
  );
  // Session itself lives inside a sensitive prefix (/private): allowed.
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "/private/tmp/proj" }, "/private/tmp/proj").block,
    false,
  );
  // Sensitive prefix that IS the session root: allowed.
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "/etc/proj" }, "/etc/proj").block,
    false,
  );
});

test("rule 4: cwd outside the session but non-sensitive passes", () => {
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "/tmp" }, SESSION).block,
    false,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "/Users/omp/other-project" }, SESSION).block,
    false,
  );
});

test("rule 4: missing or empty cwd passes", () => {
  assert.equal(guard.evaluate({ op: "start", application: "myapp", args: [] }, SESSION).block, false);
  assert.equal(guard.evaluate({ op: "start", application: "myapp", args: [], cwd: "" }, SESSION).block, false);
  assert.equal(guard.evaluate({ op: "start", application: "myapp", args: [], cwd: 42 }, SESSION).block, false);
});

test("absolute application paths are normalized by basename", () => {
  assert.equal(
    guard.evaluate({ op: "start", application: "/bin/sh", args: ["-c", "ls"] }, SESSION).block,
    true,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "/usr/bin/curl", args: ["https://example.com"] }, SESSION).block,
    true,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "/usr/bin/python3", args: ["-c", "print(1)"] }, SESSION).block,
    true,
  );
  assert.equal(
    guard.evaluate({ op: "start", application: "/opt/homebrew/bin/node", args: ["server.js"] }, SESSION).block,
    false,
  );
});

test("empty or non-string application passes safely", () => {
  const params = [
    { op: "start", application: "" },
    { op: "start", application: "   " },
    { op: "start", application: 42 },
    { op: "start", application: null },
    { op: "start", application: undefined },
    { op: "start", application: { name: "curl" } },
    { op: "start", application: ["curl"] },
  ];
  for (const p of params) {
    assert.deepEqual(guard.evaluate(p, SESSION), { block: false }, JSON.stringify(p) + " must pass");
  }
});

test("non-array args normalize to empty", () => {
  assert.equal(guard.evaluate({ op: "start", application: "bun", args: "run dev" }, SESSION).block, false);
  assert.equal(guard.evaluate({ op: "start", application: "sh", args: undefined }, SESSION).block, false);
  assert.equal(guard.evaluate({ op: "start", application: "sh", args: null }, SESSION).block, false);
  // Array elements are stringified before matching.
  assert.equal(
    guard.evaluate({ op: "start", application: "env", args: ["rm", "-rf", 42] }, SESSION).block,
    true,
  );
});

test("session cwd is normalized before the under-check", () => {
  const sessionWithSlash = SESSION + "/";
  const inside = path.join(SESSION, "sub");
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: inside }, sessionWithSlash).block,
    false,
  );
  // A sibling directory of the session is NOT under it.
  const sibling = SESSION + "-sibling";
  assert.equal(
    guard.evaluate({ op: "start", application: "myapp", args: [], cwd: sibling }, sessionWithSlash).block,
    false,
  );
});
