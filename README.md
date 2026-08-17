# smart-approve

An approval gate for **oh-my-pi (OMP)** and upstream **pi-agent**: behavior detection + LLM risk analysis decide whether a dangerous operation runs, with interactive confirmation dialogs or a fully automatic mode. Compatible with both hosts.

Covered execution surfaces:

| Tool | Mechanism | Dangerous-op handling |
|---|---|---|
| `bash` | Custom tool shadowing the built-in | regex + LLM analysis + dialog (interactive) or AI verdict (auto) |
| `eval` | Custom tool shadowing the built-in | code that starts subprocesses / runs system commands goes through the same pipeline |
| `hub` (op `start`) | `tool_call` regex gate | structured launch specs blocked on dangerous applications/args/cwd |
| `write` / `edit` on protected paths | `tool_call` path matching | confirmation dialog; symlink-aware |

Safe operations pass through with **zero interruption**. The shadowed-tool `execute()` path runs outside OMP's 30-second `EXTENSION_HANDLER_TIMEOUT_MS`, so LLM analysis and dialogs have no time pressure. In headless (subagent) contexts, dangerous operations are blocked outright — or, in auto mode with `autoInHeadless`, decided by AI.

## How it works

```
LLM calls bash / eval
       │
   ToolGate.execute() — shared decision pipeline (template method)
       ├─ hard-block (rm -rf /, fork bomb, curl|sh, eval subprocess +
       │  destructive payload…) → block always
       ├─ allow-list hit (session or permanent) → execute
       ├─ no behaviors → execute (zero interruption)
       └─ dangerous behavior → needs a verdict ↓
              │
          headless (no UI)?
              ├─ auto mode + autoInHeadless → AI decides
              └─ otherwise → block
              │
          mode: "interactive"          mode: "auto"
              │                            │
          LLM analysis (@tiny first,     LLM analysis
          @smol → @default fallback)     AutoDecisionPolicy
              │                            ├─ recommend=deny / risk ≥ threshold → block
          dialog:                          ├─ allow → execute + non-blocking notify
          session allow / permanent        └─ LLM down → autoFallback:
          allow / deny                         "regex" → deny-tier blocks, rest executes
                                               "block" → block all reviewable ops
```

Hard-block always wins — no allow-list entry, AI verdict, or mode can override it.

**hub `start`** is a separate fast path: `HubLaunchGuard` regex-checks `application` / `args` / `cwd` inside the 30s handler budget and blocks with a clear reason (no LLM, no dialog — binary verdict).

**write/edit to protected paths** is pure path matching + confirmation dialog, no LLM analysis (the path itself is sufficient signal).

## Modes and runtime switching

Two approval modes:

| Mode | Dangerous operations |
|---|---|
| `interactive` (default) | LLM analysis shown in a dialog; you choose session-allow / permanent-allow / deny |
| `auto` | LLM verdict decides: block or execute; no dialogs (non-blocking notifications only) |

Switch at runtime from the TUI (or RPC client) — no restart needed, and the choice persists:

```
/smart-approve              # toggle interactive <-> auto
/smart-approve auto         # switch to auto
/smart-approve interactive  # switch to interactive
/smart-approve status       # show mode, thresholds, coverage
```

The current mode is also shown as a persistent status-bar chip. The command writes only the changed keys back to `smart-approve.json` — every other user-edited field is preserved.

Auto-mode decision rules:

- `recommend: "deny"` blocks; `risk` at or above `autoBlockRisk` blocks; `risk=high` but `recommend=allow` blocks (the stricter signal wins — command text is untrusted input).
- LLM chain failure (all of @tiny → @smol → @default) falls back to `autoFallback`: `"regex"` lets the regex deny tier decide (hard-block patterns always block), `"block"` blocks every reviewable operation.
- Auto-mode approvals are **not** written to the allow-list (AI verdicts can change; remembered approvals should stay human decisions).
- Deny tier (regex-confident, blocks without any LLM verdict): force-push to `main`/`master`/`production`/`prod`/`release`/`trunk`, `rm -rf ~` / `$HOME`, block-device writes.

## Architecture

Object-oriented, dependency-inverted; every concern is a class:

```
SmartApprove (orchestrator)
 ├─ ConfigStore          — config load + runtime update + selective write-back
 ├─ ModeManager          — runtime mode switching + status
 ├─ AllowList            — session + permanent decision memory
 ├─ AutoDecisionPolicy   — pure auto-mode verdict rules (thresholds, fallback)
 ├─ ToolGate (abstract, template method) — shared decision pipeline
 │    ├─ BashToolGate    — command analysis, cd-prefix cwd, native delegation
 │    └─ EvalToolGate    — code analysis (subprocess intent), native delegation
 ├─ EvalCodeBehaviorAnalyzer — eval code patterns (comments/strings scrubbed)
 └─ HubLaunchGuard       — hub op:"start" regex rules
```

`ToolGate` defines the invariant flow (hard-block → allow-list → no-behavior → headless → verdict → remember → delegate); each concrete gate implements three hooks — `analyze()` / `buildKey()` / `delegate()` — plus its schema and subject extraction. Adding a new covered tool means adding one subclass, not touching the pipeline. Collaborators are injected as narrow interfaces (`AllowListLike`, `ModelInvokerLike`, `LoggerLike`), so the branch matrix is unit-testable without a running host.

## LLM risk analysis: persistent RPC session

Risk analysis does **not** cold-start a new `omp -p` subprocess per call. Instead, the extension spawns **one** `omp --mode rpc` child on first use and reuses it over a JSONL stdio protocol for every analysis in the session:

- **One process, many prompts** — extension loading (including `provider-retry-proxy`) and process startup are paid once per host session, not per analysis
- **Per-attempt timeout** — each prompt is bounded by `analysisTimeoutMs` (default 30s, `0` = no timeout); a hung remote model cannot freeze the covered tools
- **Model fallback chain** — @tiny first (cheapest), then @smol, then @default; each attempt time-bounded; total failure degrades per `mode` (rule-label dialog, or `autoFallback`)
- **Interruption** — the tool's `AbortSignal` is forwarded to the RPC child (`abort` command), so a user interrupt cancels an in-flight analysis instead of leaving it running
- **Lifecycle** — the child is lazily spawned on first use, killed via `session_shutdown`, reaped after `rpcIdleTimeoutMs` (default 10 min) of inactivity, and exits on its own if the host dies (stdin EOF closes → process exits code 0, no orphans)

The LLM receives: session context (original user task + recent agent plan, injection-guarded), detected behavior labels, and the subject (command or code). It returns structured JSON: `risk` (low/medium/high), `summary`, `detail`, `recommend`.

## Features

### 1. Behavior-based detection (bash)

Parses git arguments to detect behaviors that regex alone misses:

| Command | Behavior detected | How |
|---|---|---|
| `git push origin +main` | force-push | `+`refspec, not just `--force` |
| `git push -f origin main` | force-push to protected branch | deny tier (branch-aware) |
| `git branch -D feature` | branch-delete | combined short flags like `-rD` |
| `git clean -fd` | git-clean | `--dry-run` excluded |
| `git reset --hard` | hard-reset | `--hard` flag |
| `git worktree remove` | worktree-remove | subcommand parsing |

Regex rules remain as a secondary net covering 30+ patterns: `rm -rf` (case-insensitive, including `-Rf`/`-RF` and `--recursive --force`), fork bombs, `curl|sh`, `mkfs`, `dd`, `kill -9`, `sudo`, `docker rm`, `kubectl delete`, 20+ git destructive operations, and more.

### 2. eval code analysis

`EvalCodeBehaviorAnalyzer` scrubs comments and string literals before matching, then detects code that starts subprocesses or runs system commands:

- **JS/Bun**: ``Bun.$`…` ``, `Bun.spawn`, `Bun.spawnSync`, `Bun.shell`, `child_process` imports, `execSync` / `execFile` / `spawnSync` (bare `exec()`/`spawn()` only count with a `child_process` import — precision over recall)
- **Python**: `subprocess` imports/`run`/`Popen`, `os.system`, `os.popen`, `os.exec*`, `shell=True`

When subprocess intent co-occurs with a destructive payload (`rm -rf /`/`~`, fork bomb, `curl … | sh`, `dd of=/dev/…`, `mkfs`, writes to `/etc/passwd` etc., shutdown), the code is hard-blocked. Eval dialogs offer session-allow only (permanent remember of code is meaningless). Kernel state, output truncation and cancellation stay with the native tool — execution is delegated via `ctx.invokeTool`.

### 3. hub launch guard

`hub op:"start"` calls are checked against four rules (any hit blocks):

1. hard-rejected applications: `osascript`, `sudo`, `ssh`, `scp`, `nc`, `netcat`, `ncat`, `socat`, `telnet`, `openssl`, `curl`, `wget`
2. interpreter + execution flag: `sh`/`bash`/`node`/`bun`/`python`/… with `-c`, `-e`, `--eval`, `--command`, `-i` (so `bun run dev` still works)
3. dangerous payload anywhere in the args (`rm -rf`, `chmod`, `chown`, `dd … of=`, `mkfs`, shutdown, `/etc/passwd`, …)
4. sensitive working directory (`/etc`, `~/.ssh`, …) outside the session workspace

### 4. Protected path interception (write/edit)

Intercepts `write`/`edit` tool calls and matches the target path against glob patterns:

- `.env`, `.env.*` (`.env.example` explicitly allowed)
- `**/.ssh/**`, `**/.kube/config`, `**/.aws/credentials`
- `**/.git-credentials`, `**/.netrc`, `**/.npmrc`, `**/.pypirc`
- `**/id_rsa`, `**/id_ed25519`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.kdbx`
- `**/auth.json`, `**/.config/gh/hosts.yml`, `**/.config/gcloud/**`

Matching is **symlink-aware**: resolves `realpath` before matching, so a symlink alias can't evade a deny. Pure and fast — no LLM analysis needed.

### 5. Decision memory

The interactive dialog offers three choices (two for eval):

| Option | Storage | Lifetime |
|---|---|---|
| Allow for this session | In-memory `Set<string>` | Cleared on restart |
| Always allow | `~/.omp/agent/smart-approve-allow.json` | Persists across restarts |
| Deny | — | Blocks the operation |

Keys are scoped to `tool + normalized-content + cwd`, so the same command in a different project still triggers review. When the UI doesn't support `select`, it degrades to a simple `confirm` (two-way).

### 6. Hard-block behaviors

Always hard-blocked — no LLM review, no dialog, no allow-list override:

- Delete root path (`rm -rf /`), delete home directory (`rm -rf ~`)
- Fork bombs
- Remote fetch-and-execute (`curl|sh`)
- Writes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`
- Writes to raw block devices (`/dev/sd*`, `/dev/nvme*`, …)
- Disk format (`mkfs`, `dd` to block device)
- Shutdown / reboot
- eval: subprocess invocation combined with any of the destructive payloads above

### 7. Execution via native tool delegation

Operations are never executed by the extension itself. After passing the approval gate, execution is delegated to the native built-in via `ctx.invokeTool()`, inheriting all native behavior:

- **Shell path resolution** — no ENOENT from missing PATH in worker processes
- **PTY support** — interactive commands work when the native tool uses PTY
- **Env hardening** — `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, etc.
- **Output truncation** — head/tail windows with artifact spill
- **Retained eval kernels** — code still sees persistent state, `reset` still works
- **Cross-platform** — no hardcoded binary paths

## Known boundaries (honest scope)

- eval/browser code that starts subprocesses is detected **statically** (text patterns on the code). Code that evades the patterns (obfuscated imports, dynamic constructors) is not caught — this is an approval gate, not a sandbox.
- `github`, `debug`, `browser`, `computer`, and MCP tools are not covered by this extension. `debug` has a native approval prompt available (`tools.approval.debug: prompt`); recommend the same for any other tool you want gated natively.
- `hub` gating is binary regex (no LLM analysis, no dialog).
- Permanent allow-list entries predate rule upgrades; hard-blocks always win over them.

## Install

```sh
npm install smart-approve
```

Then configure OMP to load the extension:

```yaml
# ~/.omp/agent/config.yml   (or ~/.pi/agent/config.yml for pi-agent)
extensions:
  - smart-approve
tools:
  approvalMode: yolo
```

- `tools.approvalMode: yolo` — auto-approve safe operations; this extension is the sole gate for dangerous ones
- `extensions: [smart-approve]` — load the extension from `node_modules`

The custom "bash"/"eval" tools shadow the built-ins by name — no `bash.enabled` change is needed. Restart the host after installing or editing.

## Configuration

Config lives at `~/.omp/agent/smart-approve.json` (or `~/.pi/agent/smart-approve.json` on pi-agent). All fields are optional — defaults apply when missing:

```json
{
  "enabled": true,
  "mode": "interactive",
  "autoBlockRisk": "high",
  "autoFallback": "regex",
  "autoInHeadless": false,
  "coverage": { "eval": true },
  "protectedPaths": [
    ".env", ".env.*", "!.env.example",
    "**/.ssh/**", "**/.kube/config", "**/.aws/credentials",
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.kdbx",
    "**/id_rsa", "**/id_ed25519", "**/auth.json"
  ],
  "llmAnalysis": true,
  "rememberDecisions": true,
  "contextMaxChars": 3000,
  "analysisTimeoutMs": 30000,
  "rpcIdleTimeoutMs": 600000,
  "model": "@tiny"
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch |
| `mode` | `"interactive"` | `"interactive"` (dialogs) or `"auto"` (AI decides, no dialogs). Switchable at runtime via `/smart-approve` |
| `autoBlockRisk` | `"high"` | Auto mode: AI risk at or above this level blocks (`"high"` or `"medium"`) |
| `autoFallback` | `"regex"` | Auto mode when the LLM chain fails: `"regex"` (hard-block + deny tier still block, rest executes) or `"block"` (everything reviewable blocks) |
| `autoInHeadless` | `false` | Auto mode also applies in headless/subagent sessions (AI decides instead of blanket block) |
| `coverage.eval` | `true` | Shadow the `eval` tool; set `false` on hosts without a native eval tool |
| `protectedPaths` | 20+ built-in patterns | Glob patterns for write/edit interception; `!` prefix negates |
| `llmAnalysis` | `true` | Whether to invoke the model for risk analysis; `false` = rule-only |
| `rememberDecisions` | `true` | Whether to offer remember options in the dialog |
| `contextMaxChars` | `3000` | Max chars of session context to feed the LLM |
| `analysisTimeoutMs` | `30000` | Per-attempt timeout for the RPC risk-analysis prompt in ms; `0` = no timeout. On timeout/failure the model chain advances @tiny → @smol → @default, then falls back per mode |
| `rpcIdleTimeoutMs` | `600000` | Idle lifetime of the persistent RPC child in ms; `0` = keep alive until session end |
| `model` | `@tiny` | Model spec for risk analysis (role alias, provider/id, or bare id) |

## Allow-list (decision memory)

Permanent allow entries are stored at `~/.omp/agent/smart-approve-allow.json`:

```json
{
  "permanent": [
    {
      "tool": "bash",
      "key": "git push origin main",
      "cwd": "/home/user/myproject",
      "timestamp": "2026-07-23T05:00:00.000Z"
    }
  ]
}
```

Session allows are in-memory only, cleared on restart. You can edit or delete this file to revoke remembered decisions.

## Extension API surface used

| API | Purpose |
|---|---|
| `pi.registerTool({ name, parameters, execute })` | Custom "bash"/"eval" tools shadowing the built-ins |
| `pi.zod` | Injected zod module for tool parameter schemas |
| `ctx.invokeTool(params, opts)` | Delegate execution to the native tool of the same name |
| `child_process.spawn(hostBin, ["--mode", "rpc", ...])` | Persistent RPC child for LLM risk analysis |
| `pi.on("tool_call", handler)` | hub launch gating + write/edit protected-path interception |
| `pi.on("session_start" / "session_shutdown")` | Status chip / RPC child cleanup |
| `pi.registerCommand("smart-approve", …)` | Runtime mode switching + status |
| `ctx.hasUI` | Detect headless/subagent context |
| `ctx.sessionManager.getBranch()` / `getEntries()` | Gather session context for LLM review |
| `ctx.ui.setStatus / notify / confirm / select` | Status, notifications, dialogs |
| `return { block: true, reason }` | Block contract for `tool_call` handlers |

## Project layout

```
smart-approve/
├── README.md
├── package.json          ← omp.extensions / pi.extensions manifest
├── LICENSE               ← MIT
├── src/
│   ├── index.ts          ← SmartApprove orchestrator: wiring + commands + hooks
│   ├── gate.ts           ← ToolGate (abstract template method) + dep contracts
│   ├── bash-tool.ts      ← BashToolGate (shadows built-in, delegates)
│   ├── eval-tool.ts      ← EvalToolGate (shadows built-in, delegates)
│   ├── policy.ts         ← AutoDecisionPolicy (auto-mode verdict rules)
│   ├── mode-manager.ts   ← ModeManager (runtime switching + status)
│   ├── behaviors.ts      ← bash behavior catalog (hard/deny/review tiers) + git parser
│   ├── eval-analyzer.ts  ← EvalCodeBehaviorAnalyzer (subprocess intent)
│   ├── hub-guard.ts      ← HubLaunchGuard (hub op:"start" regex rules)
│   ├── types.ts          ← ExtensionAPI, ToolDefinition, DangerAnalysis, …
│   ├── host.ts           ← HostResolver + ModelInvoker (persistent RPC)
│   ├── rpc-invoker.ts    ← RPC client: spawn/reuse/kill omp --mode rpc child
│   ├── paths.ts          ← ProtectedPathMatcher (symlink-aware)
│   ├── config.ts         ← ConfigStore (load / update / persist)
│   ├── allowlist.ts      ← AllowList (session + permanent)
│   ├── context.ts        ← SessionContextGatherer
│   ├── dialog.ts         ← confirmWithRemember + formatAnalysis
│   ├── i18n.ts           ← locale detection + bilingual strings (zh/en)
│   ├── logger.ts         ← Logger (+ LoggerLike contract)
│   ├── *.test.ts         ← unit tests (bun test src)
│   └── utils/
│       └── rotating-log.ts
└── dist/
    └── index.js          ← bundled output (bun build)
```

### Runtime artifacts

```
~/.omp/agent/smart-approve.json          — config (user-editable; mode toggles persist here)
~/.omp/agent/smart-approve-allow.json    — permanent allow-list (auto-maintained)
~/.omp/logs/smart-approve.log            — diagnostic log
```

## License

MIT
