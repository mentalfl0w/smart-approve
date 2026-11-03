import assert from "node:assert/strict";
import { test } from "node:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ProtectedPathMatcher } from "./paths.ts";

test("protected relative paths resolve from the session working directory", () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-paths-"));
  try {
    const matcher = new ProtectedPathMatcher(["**/.aws/credentials"]);
    assert.equal(matcher.isProtected("nested/.aws/credentials", cwd), true);
    assert.equal(matcher.isProtected("nested/.aws/config", cwd), false);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
