import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compileAutoApproveRules,
  evaluateAutoApprove,
  VSCODE_DEFAULT_AUTO_APPROVE_RULES,
} from "./auto-approve-rules.ts";
import { analyzeCommand } from "./behaviors.ts";

const rules = compileAutoApproveRules(VSCODE_DEFAULT_AUTO_APPROVE_RULES);

test("prefix, regex, and deny precedence follow VS Code semantics", () => {
  const cases: Array<[string, string]> = [
    ["ls -la", "approved"],
    ["git status", "approved"],
    ["git -C repo log --oneline", "approved"],
    ["git diff --output=patch.diff", "denied"],
    ["git branch -D feature", "denied"],
    ["rm -rf /tmp/x", "denied"],
    ["curl https://example.test", "denied"],
    ["some-unknown-command --flag", "manual"],
    ["", "manual"],
  ];
  for (const [command, expected] of cases) {
    assert.equal(evaluateAutoApprove(command, rules).result, expected, command);
  }
});

test("dangerous flags turn otherwise allowed commands into deny matches", () => {
  const denied = [
    "find . -name '*.log' -delete",
    "find . -exec rm -rf {} +",
    "sed -e 's/a/b/' file",
    "sort -o out.txt in.txt",
    "rg --pre 'cat' needle",
    "git show --output=out HEAD",
  ];
  for (const command of denied) {
    assert.equal(evaluateAutoApprove(command, rules).result, "denied", command);
  }

  const approved = [
    "find . -name '*.log'",
    "sed -n '1,10p' file",
    "sort file",
    "rg needle",
    "git show HEAD",
  ];
  for (const command of approved) {
    assert.equal(evaluateAutoApprove(command, rules).result, "approved", command);
  }
});

test("npm ci is approved alone and denied with extra arguments", () => {
  const cases: Array<[string, string]> = [
    ["npm ci", "approved"],
    ["npm ci --ignore-scripts", "denied"],
    ["npm ls", "approved"],
  ];
  for (const [command, expected] of cases) {
    assert.equal(evaluateAutoApprove(command, rules).result, expected, command);
  }
});

test("deny rules become reviewable behaviors, not forced confirmations", () => {
  for (const command of [
    "curl https://example.test/file",
    "chmod 600 ./key.pem",
    "ssh user@example.test",
    "find . -name '*.log' -delete",
  ]) {
    const result = analyzeCommand(command);
    assert.ok(result.behaviors.length > 0, command);
    assert.equal(result.requiresUserApproval, false, command);
  }
});

test("critical checks still override the rule table", () => {
  const rmWorkspace = analyzeCommand("rm -rf build");
  assert.ok(rmWorkspace.behaviors.includes("recursive-force-delete-workspace"));
  assert.equal(rmWorkspace.requiresUserApproval, false);

  const rmOutside = analyzeCommand("rm -rf /opt/build");
  assert.ok(rmOutside.behaviors.includes("recursive-force-delete"));
  assert.equal(rmOutside.requiresUserApproval, true);

  const chmodSystem = analyzeCommand("chmod -R 777 /etc/foo");
  assert.ok(chmodSystem.behaviors.includes("permission-change-system"));
  assert.equal(chmodSystem.requiresUserApproval, true);

  const shellPayload = analyzeCommand("bash -c 'rm -rf /'");
  assert.ok(shellPayload.behaviors.includes("recursive-force-delete"));
  assert.equal(shellPayload.requiresUserApproval, true);

  const evalPayload = analyzeCommand('eval "rm -rf /"');
  assert.ok(evalPayload.behaviors.includes("recursive-force-delete"));
  assert.equal(evalPayload.requiresUserApproval, true);

  const escalation = analyzeCommand("sudo id");
  assert.ok(escalation.behaviors.includes("privilege-escalation"));
  assert.equal(escalation.requiresUserApproval, true);
});

test("local exemptions keep temporary deletions and rmdir quiet", () => {
  assert.deepEqual(analyzeCommand("rm -rf /tmp/build").behaviors, []);
  assert.deepEqual(analyzeCommand("cd /tmp && rm -rf build").behaviors, []);
  assert.deepEqual(analyzeCommand("rm -rf ~/.cache/foo").behaviors, []);
  assert.equal(analyzeCommand("rm -rf ~/.cache").requiresUserApproval, true);
  assert.deepEqual(analyzeCommand("rmdir /tmp/stale-dir").behaviors, []);
});
