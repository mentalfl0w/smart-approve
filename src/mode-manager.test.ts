/**
 * ModeManager + ConfigStore runtime mutation/persistence round-trip,
 * using an injected temp config dir (never touches the user's real config).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ConfigStore } from "./config.ts";
import { ModeManager } from "./mode-manager.ts";
import type { LoggerLike } from "./logger.ts";

const silentLogger: LoggerLike = { log: () => undefined };

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "smart-approve-test-"));
}

function makeManager(dir: string, coverage = { eval: true, hub: true }) {
  const store = new ConfigStore(silentLogger, dir);
  return { store, manager: new ModeManager(store, silentLogger, coverage) };
}

test("default mode is interactive; toggle switches to auto and persists", () => {
  const dir = tempDir();
  const { store, manager } = makeManager(dir);
  assert.equal(store.config.mode, "interactive");

  const next = manager.toggle();
  assert.equal(next, "auto");
  assert.equal(store.config.mode, "auto");

  const onDisk = JSON.parse(fs.readFileSync(path.join(dir, "smart-approve.json"), "utf-8"));
  assert.equal(onDisk.mode, "auto");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("persist preserves other user-authored keys", () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "smart-approve.json"),
    JSON.stringify({ llmAnalysis: false, model: "@smol", customKey: "keep-me" }),
    "utf-8",
  );
  const { store, manager } = makeManager(dir);

  assert.equal(store.config.llmAnalysis, false);
  manager.set("auto");

  const onDisk = JSON.parse(fs.readFileSync(path.join(dir, "smart-approve.json"), "utf-8"));
  assert.equal(onDisk.mode, "auto");
  assert.equal(onDisk.llmAnalysis, false);
  assert.equal(onDisk.model, "@smol");
  assert.equal(onDisk.customKey, "keep-me");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("set to the current mode is a no-op that still persists cleanly", () => {
  const dir = tempDir();
  const { manager } = makeManager(dir);
  assert.equal(manager.set("interactive"), "interactive");
  assert.equal(manager.toggle(), "auto");
  assert.equal(manager.toggle(), "interactive");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("status block reports mode and coverage", () => {
  const dir = tempDir();
  const { store, manager } = makeManager(dir, { eval: false, hub: true });
  const status = manager.status();
  assert.match(status, /mode: interactive/);
  assert.match(status, /coverage: eval=false hub=true/);
  fs.rmSync(dir, { recursive: true, force: true });
});
