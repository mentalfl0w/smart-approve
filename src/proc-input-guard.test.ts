import assert from "node:assert/strict";
import { test } from "node:test";
import {
  applyProcServiceMode,
  classifyInteractiveService,
  forgetProcService,
  forgetSessionServices,
  getTrackedServiceCwd,
  procServiceModeChange,
  resolveTrackedServiceInput,
  sessionIdOf,
  setTrackedServiceCwd,
  trackInteractiveService,
} from "./proc-input-guard.ts";

const NAME = "smart-approve-test-shell";

test("only identifiable interactive interpreters are tracked for proc stdin checks", () => {
  assert.equal(classifyInteractiveService("bash"), "shell");
  assert.equal(classifyInteractiveService("/bin/zsh -i"), "shell");
  assert.equal(classifyInteractiveService("python3"), "python");
  assert.equal(classifyInteractiveService("node"), "javascript");

  assert.equal(classifyInteractiveService("bash -c 'echo ready'"), undefined);
  assert.equal(classifyInteractiveService("bash # interactive"), "shell");
  assert.equal(classifyInteractiveService("# start a shell\nbash"), "shell");
  assert.equal(classifyInteractiveService("bash#not-a-comment"), undefined);
  assert.equal(classifyInteractiveService("python3 server.py"), undefined);
  assert.equal(classifyInteractiveService("node server.js"), undefined);
  assert.equal(classifyInteractiveService("bun run dev"), undefined);
  assert.equal(classifyInteractiveService("cd /etc && bash"), "shell");
  assert.equal(classifyInteractiveService("cd /etc; bash"), "shell");
  assert.equal(classifyInteractiveService("cd /etc\nbash"), "shell");
  assert.equal(classifyInteractiveService("cd /etc # note\nbash"), "shell");
  assert.equal(classifyInteractiveService("# note\ncd /etc && bash"), "shell");
  assert.equal(classifyInteractiveService("cd /etc && echo safe && bash"), undefined);
});

test("recognizes common command wrappers without treating script launches as REPLs", () => {
  assert.equal(classifyInteractiveService("env -i bash"), "shell");
  assert.equal(classifyInteractiveService("sudo -u root /bin/bash"), "shell");
  assert.equal(classifyInteractiveService("python3 -i app.py"), "python");
});

test("bare sudo login/shell shorthands are interactive shells, with commands not REPLs", () => {
  assert.equal(classifyInteractiveService("sudo -i"), "shell");
  assert.equal(classifyInteractiveService("sudo -s"), "shell");
  assert.equal(classifyInteractiveService("sudo --login"), "shell");
  assert.equal(classifyInteractiveService("sudo --shell"), "shell");
  assert.equal(classifyInteractiveService("sudo -n -s"), "shell");
  assert.equal(classifyInteractiveService("sudo -iu root"), "shell");
  assert.equal(classifyInteractiveService("sudo -i # login shell"), "shell");
  assert.equal(classifyInteractiveService("env -i sudo --login"), "shell");

  assert.equal(classifyInteractiveService("sudo -i ls"), undefined);
  assert.equal(classifyInteractiveService("sudo -s apt update"), undefined);
  assert.equal(classifyInteractiveService("sudo --login echo hi"), undefined);
  assert.equal(classifyInteractiveService("sudo ls"), undefined);
  assert.equal(classifyInteractiveService("sudo -u root /bin/bash script.sh"), undefined);
});

test("optional session id surface tolerates hosts without OMP APIs", () => {
  assert.equal(sessionIdOf(undefined), undefined);
  assert.equal(sessionIdOf({}), undefined);
  assert.equal(sessionIdOf({ sessionManager: {} }), undefined);
  assert.equal(sessionIdOf({ sessionManager: { getSessionId: () => "  session-1 " } }), "session-1");
  assert.equal(sessionIdOf({ sessionManager: { getSessionId: () => "" } }), undefined);
});

test("proc stdin checks ignore unknown processes, empty input, and control URLs", () => {
  forgetProcService(NAME, "/work/project");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "rm -rf /"), undefined);
  assert.equal(resolveTrackedServiceInput("proc://unknown", "rm -rf /"), undefined);
  assert.equal(resolveTrackedServiceInput("proc://unknown", ""), undefined);
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}/kill`, "rm -rf /"), undefined);
});

test("tracked interactive service input carries its runtime and working directory", () => {
  forgetProcService(NAME, "/work/project");
  trackInteractiveService(NAME, "bash", "/work/project", "/work/project");
  assert.deepEqual(resolveTrackedServiceInput(`proc://${NAME}`, "git push --force", "/work/project"), {
    name: NAME,
    runtime: "shell",
    command: "git push --force",
    cwd: "/work/project",
  });
  forgetProcService(NAME, "/work/project");

  trackInteractiveService(NAME, "python3", "/work/service", "/work/project");
  assert.deepEqual(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", "/work/project"), {
    name: NAME,
    runtime: "python",
    command: "print(1)",
    cwd: "/work/service",
  });
  forgetProcService(NAME, "/work/project");
});

test("tracked service cwd can follow static chdir changes", () => {
  const workspace = "/work/project";
  forgetProcService(NAME, workspace);
  trackInteractiveService(NAME, "python3", "/work/a", workspace, "session-a");
  assert.equal(getTrackedServiceCwd(NAME, workspace), "/work/a");
  setTrackedServiceCwd(NAME, "/work/b", workspace);
  assert.equal(getTrackedServiceCwd(NAME, workspace), "/work/b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", workspace)?.cwd, "/work/b");
  forgetProcService(NAME, workspace);
});

test("public proc names are project-unique; session id is owner metadata, not a lookup partition", () => {
  const workspace = "/work/project";
  forgetProcService(NAME, workspace);
  trackInteractiveService(NAME, "bash", "/work/a", workspace, "session-a");

  // Another session still targets the project-unique service by name.
  assert.deepEqual(resolveTrackedServiceInput(`proc://${NAME}`, "git push --force", workspace, "session-b"), {
    name: NAME,
    runtime: "shell",
    command: "git push --force",
    cwd: "/work/a",
  });

  // A cross-session named-service replacement with a non-REPL command must
  // clear the previous classifier instead of inheriting it.
  trackInteractiveService(NAME, "bash -c 'echo hi'", "/work/x", workspace, "session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace), undefined);

  // Re-registering the same public name transfers ownership for cleanup.
  trackInteractiveService(NAME, "python3", "/work/b", workspace, "session-b");
  forgetSessionServices("session-a");
  assert.deepEqual(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", workspace), {
    name: NAME,
    runtime: "python",
    command: "print(1)",
    cwd: "/work/b",
  });

  forgetSessionServices("session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", workspace), undefined);
});

test("non-REPL named-service replacement clears a cross-session classifier", () => {
  const workspace = "/work/project";
  forgetProcService(NAME, workspace);
  trackInteractiveService(NAME, "bash", "/work/a", workspace, "session-a");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace)?.runtime, "shell");

  // OMP restarts a live project-unique name with the new spec.
  trackInteractiveService(NAME, "bash -c 'echo hi'", "/work/b", workspace, "session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace), undefined);
});

test("session cleanup removes only services owned by the ending session", () => {
  const workspace = "/work/project";
  const other = `${NAME}-other`;
  forgetProcService(NAME, workspace);
  forgetProcService(other, workspace);

  trackInteractiveService(NAME, "bash", "/work/a", workspace, "session-a");
  trackInteractiveService(other, "python3", "/work/b", workspace, "session-b");

  forgetSessionServices("session-a");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace), undefined);
  assert.deepEqual(resolveTrackedServiceInput(`proc://${other}`, "print(1)", workspace), {
    name: other,
    runtime: "python",
    command: "print(1)",
    cwd: "/work/b",
  });

  // A stale session-scoped forget must not remove another owner's entry.
  forgetProcService(other, workspace, "session-a");
  assert.deepEqual(resolveTrackedServiceInput(`proc://${other}`, "print(1)", workspace), {
    name: other,
    runtime: "python",
    command: "print(1)",
    cwd: "/work/b",
  });
  // An unconditional exit/kill report is authoritative.
  forgetProcService(other, workspace);
  assert.equal(resolveTrackedServiceInput(`proc://${other}`, "print(1)", workspace), undefined);
});

test("detached and persist modes survive owner-session shutdown", () => {
  const workspace = "/work/project";
  forgetProcService(NAME, workspace);
  assert.deepEqual(procServiceModeChange(`proc://${NAME}/mode`, " detached "), {
    name: NAME,
    mode: "detached",
  });
  assert.equal(procServiceModeChange(`proc://${NAME}`, "detached"), undefined);
  assert.equal(procServiceModeChange(`proc://${NAME}/mode`, "bogus"), undefined);
  assert.equal(procServiceModeChange(`proc://${NAME}/mode`, "constructor"), undefined);

  trackInteractiveService(NAME, "bash", "/work/a", workspace, "session-a");
  assert.equal(applyProcServiceMode(NAME, "detached", workspace), true);
  forgetSessionServices("session-a");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace)?.runtime, "shell");

  // Returning to session lifetime re-homes cleanup to the writing session.
  assert.equal(applyProcServiceMode(NAME, "session", workspace, "session-b"), true);
  forgetSessionServices("session-a");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace)?.runtime, "shell");
  forgetSessionServices("session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace), undefined);

  // A detached service's exit observed by another session still clears it.
  trackInteractiveService(NAME, "bash", "/work/d", workspace, "session-d");
  assert.equal(applyProcServiceMode(NAME, "detached", workspace), true);
  forgetProcService(NAME, workspace, "session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", workspace), undefined);

  trackInteractiveService(NAME, "python3", "/work/p", workspace, "session-c");
  assert.equal(applyProcServiceMode(NAME, "persist", workspace), true);
  forgetSessionServices("session-c");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", workspace)?.runtime, "python");
  forgetProcService(NAME, workspace);
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", workspace), undefined);
});

test("services with the same name in different workspaces stay isolated", () => {
  trackInteractiveService(NAME, "bash", "/work/a", "/work/a", "session-a");
  trackInteractiveService(NAME, "python3", "/work/b", "/work/b", "session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", "/work/a")?.runtime, "shell");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", "/work/b")?.runtime, "python");
  forgetSessionServices("session-a");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "ls", "/work/a"), undefined);
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", "/work/b")?.runtime, "python");
  forgetSessionServices("session-b");
  assert.equal(resolveTrackedServiceInput(`proc://${NAME}`, "print(1)", "/work/b"), undefined);
});
