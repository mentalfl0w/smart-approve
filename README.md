# smart-approve

A custom "bash" tool that replaces OMP's built-in bash, with LLM-powered risk analysis, behavior detection, protected-path interception, and decision memory. Compatible with both **oh-my-pi (OMP)** and upstream **pi-agent**.

Safe commands pass through with **zero interruption**. When a dangerous behavior is detected, the custom tool's `execute()` method runs LLM risk analysis and shows an approval dialog — all outside OMP's 30-second `EXTENSION_HANDLER_TIMEOUT_MS`, so there is no time pressure. In headless (subagent) contexts, dangerous operations are blocked outright.

## How it works

```
LLM calls bash tool
       │
   allow-list hit (session or permanent)? ── yes → execute
       │ no
   analyzeCommand() — argument parsing + regex secondary net
       ├─ no behaviors → execute (zero interruption)
       ├─ hard-block (rm -rf /, fork bomb, curl|sh…) → block always
       └─ dangerous behavior → needs review ↓
              │
          ctx.hasUI === false (headless) → block
              │ has UI:
              setStatus("analyzing…")
              gatherSessionContext() — original user task + recent agent plan
              omp -p --model @smol (no timeout, runs to completion)
                  @smol unconfigured? → retry with @default
                  success → dialog shows risk / summary / detail / recommendation
                  failure → dialog shows rule-based label only
              ctx.ui.select(title, [session allow, permanent allow, deny])
                  session   → in-memory Set (cleared on restart)
                  permanent → persisted to JSON file
                  deny      → block
              approved → pi.exec("bash", ["-c", cmd]) → return output to LLM
```

**write/edit to protected paths** is handled separately via the `tool_call` hook — pure path matching + confirmation dialog, no LLM analysis (the path itself is sufficient signal).

## Architecture: custom tool, not handler interception

OMP's `EXTENSION_HANDLER_TIMEOUT_MS` (30s, hardcoded) wraps `tool_call` event handler dispatch — but **not** custom tool `execute()` methods. This extension exploits that:

1. `config.yml: bash.enabled: false` — removes OMP's built-in bash tool
2. `pi.registerTool({ name: "bash", ... })` — registers a replacement with the same name
3. All approval logic (behavior detection → LLM analysis → `ui.select` → execution) lives inside `execute()`, free from the 30s timeout

The previous architecture intercepted bash via `pi.on("tool_call")` and was killed by the 30s timeout during LLM analysis. The custom tool architecture eliminates this entirely.

## Features

### 1. Behavior-based detection (not just regex)

Parses git arguments to detect behaviors that regex alone misses:

| Command | Behavior detected | How |
|---|---|---|
| `git push origin +main` | force-push | `+`refspec, not just `--force` |
| `git branch -D feature` | branch-delete | combined short flags like `-rD` |
| `git clean -fd` | git-clean | `--dry-run` excluded |
| `git reset --hard` | hard-reset | `--hard` flag |
| `git worktree remove` | worktree-remove | subcommand parsing |

Regex rules remain as a secondary net covering 30+ patterns: `rm -rf`, fork bombs, `curl|sh`, `mkfs`, `dd`, `kill -9`, `sudo`, `docker rm`, `kubectl delete`, 20+ git destructive operations, and more.

### 2. Protected path interception (write/edit)

Intercepts `write`/`edit` tool calls via the `tool_call` hook and matches the target path against glob patterns:

- `.env`, `.env.*` (`.env.example` explicitly allowed)
- `**/.ssh/**`, `**/.kube/config`, `**/.aws/credentials`
- `**/.git-credentials`, `**/.netrc`, `**/.npmrc`, `**/.pypirc`
- `**/id_rsa`, `**/id_ed25519`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.kdbx`
- `**/auth.json`, `**/.config/gh/hosts.yml`, `**/.config/gcloud/**`

Matching is **symlink-aware**: resolves `realpath` before matching, so a symlink alias can't evade a deny.

Path matching is pure and fast — no LLM analysis needed. The 30s handler budget is more than sufficient for path matching + confirmation dialog.

### 3. Decision memory

The confirmation dialog offers three choices:

| Option | Storage | Lifetime |
|---|---|---|
| Allow for this session | In-memory `Set<string>` | Cleared on restart |
| Always allow | `~/.omp/agent/smart-approve-allow.json` | Persists across restarts |
| Deny | — | Blocks the command |

Keys are scoped to `tool + normalized-content + cwd`, so the same command in a different project still triggers review. When the UI doesn't support `select`, it degrades to a simple `confirm` (two-way).

### 4. LLM risk analysis (no timeout)

The custom bash tool's `execute()` invokes the `@smol` model via the host binary's print mode (`omp -p --no-tools --no-session ...`). If `@smol` is unconfigured or fails, it automatically retries with `@default`. The subprocess runs to completion — no timeout is applied.

The LLM receives:
- **Session context** — original user task + recent agent plan (injection-guarded)
- **Detected behaviors** — localized labels
- **The command** — as-is

And returns structured JSON: `risk` (low/medium/high), `summary`, `detail`, `recommend`.

### 5. Session context for LLM review

Reads the agent's conversation history via `ctx.sessionManager.getBranch()` / `getEntries()` and extracts:

- **Original user task** — the first user message (truncated to 1000 chars)
- **Recent agent plan text** — the last 2 assistant text blocks (each truncated to 800 chars)

All context is wrapped in `<untrusted_context>` blocks with injection guards. Tool outputs and tool-call arguments are explicitly excluded (largest injection surface). When `sessionManager` is unavailable, it safely degrades to `null` — LLM review still works, just without context.

### 6. Hard-block behaviors

The following behaviors are **always hard-blocked** — no LLM review, no dialog, no allow-list override:

- Delete root path (`rm -rf /`)
- Fork bombs
- Remote fetch-and-execute (`curl|sh`)
- Writes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`
- Writes to raw block devices (`/dev/sd*`, `/dev/nvme*`, …)
- Disk format (`mkfs`, `dd` to block device)
- Shutdown / reboot

### 7. Non-interactive command execution

Commands are executed via `pi.exec("bash", ["-c", cmd])` with a hardened non-interactive environment:

- `PAGER=cat`, `GIT_PAGER=cat`, `LESS=FRX` — no pager hangs
- `GIT_TERMINAL_PROMPT=0`, `SSH_ASKPASS=/usr/bin/false` — no credential prompts
- `EDITOR=true`, `VISUAL=true` — no editor launches
- `TERM=dumb`, `NO_COLOR=1`, `CI=1` — clean output
- Inherits `process.env` (including `PATH`) so all binaries are accessible

Output is truncated (20KB head + 50KB tail with elision marker) to match OMP's built-in bash tool behavior.

### 8. OMP + pi dual compatibility with graceful degradation

| Aspect | Implementation |
|---|---|
| Dual manifest | `package.json` declares both `omp.extensions` and `pi.extensions` |
| Host detection | `process.execPath` → `process.argv[1]` → PATH lookup (`omp` → `pi`) |
| LLM invocation | `omp -p` or `pi -p`, flags shared by both |
| Model fallback | `@smol` fails → retry `@default` → rule-only confirmation (no LLM) |
| Headless | `ctx.hasUI === false` blocks all dangerous operations immediately |
| Bilingual | zh/en, auto-adapts to locale (`LC_ALL` > `LC_MESSAGES` > `LANG` > macOS `AppleLocale`) |

## Install

```sh
npm install smart-approve
```

Then configure OMP to load the extension and disable the built-in bash:

```yaml
# ~/.omp/agent/config.yml   (or ~/.pi/agent/config.yml for pi-agent)
extensions:
  - smart-approve
bash:
  enabled: false
tools:
  approvalMode: yolo
```

- `bash.enabled: false` — removes OMP's built-in bash tool so the custom tool can replace it
- `tools.approvalMode: yolo` — auto-approve safe commands; this extension is the sole gate for dangerous ones
- `extensions: [smart-approve]` — load the extension from `node_modules`

Restart the host after installing or editing.

## Configuration

Config lives at `~/.omp/agent/smart-approve.json` (or `~/.pi/agent/smart-approve.json` on pi-agent). All fields are optional — defaults apply when missing:

```json
{
  "enabled": true,
  "protectedPaths": [
    ".env", ".env.*", "!.env.example",
    "**/.ssh/**", "**/.kube/config", "**/.aws/credentials",
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.kdbx",
    "**/id_rsa", "**/id_ed25519", "**/auth.json"
  ],
  "llmAnalysis": true,
  "rememberDecisions": true,
  "contextMaxChars": 3000,
  "model": "@smol"
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch |
| `protectedPaths` | 20+ built-in patterns | Glob patterns for write/edit interception; `!` prefix negates |
| `llmAnalysis` | `true` | Whether to invoke the model for risk analysis; `false` = rule-only confirmation |
| `rememberDecisions` | `true` | Whether to offer session/permanent remember options in the dialog |
| `contextMaxChars` | `3000` | Max chars of session context to feed the LLM |
| `model` | `@smol` | Model spec for risk analysis (role alias, provider/id, or bare id); falls back to `@default` if unavailable |

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
| `pi.registerTool({ name, parameters, execute })` | Register custom "bash" tool replacing built-in |
| `pi.zod` | Injected zod module for tool parameter schemas |
| `pi.exec("bash", ["-c", cmd], opts)` | Execute approved commands |
| `pi.exec(bin, ["-p", ...], opts)` | Spawn host binary for one-shot LLM risk analysis |
| `pi.on("tool_call", handler)` | Intercept `write`/`edit` on protected paths |
| `ctx.hasUI` | Detect headless/subagent context |
| `ctx.sessionManager.getBranch()` / `getEntries()` | Gather session context for LLM review |
| `ctx.ui.setStatus(id, text)` | Show "analyzing…" status |
| `ctx.ui.confirm(title, body)` | Confirmation dialog (fallback when `select` unavailable) |
| `ctx.ui.select(title, choices)` | Three-way choice: session allow / permanent allow / deny |
| `return { block: true, reason }` | Block contract for `tool_call` handler (write/edit only) |

## Project layout

```
smart-approve/
├── README.md
├── package.json          ← omp.extensions / pi.extensions manifest (v2.4.0)
├── LICENSE               ← MIT
├── src/
│   ├── index.ts          ← SmartApprove orchestrator: register bash tool + write/edit hook
│   ├── bash-tool.ts      ← custom "bash" tool (replaces built-in)
│   ├── types.ts          ← ExtensionAPI, ToolDefinition, AgentToolResult, etc.
│   ├── host.ts           ← HostResolver + ModelInvoker (one-shot LLM via host -p)
│   ├── behaviors.ts      ← behavior catalog, git parser, composite analysis
│   ├── paths.ts          ← ProtectedPathMatcher (symlink-aware)
│   ├── config.ts         ← ConfigStore
│   ├── allowlist.ts      ← AllowList (session + permanent)
│   ├── context.ts        ← SessionContextGatherer
│   ├── dialog.ts         ← confirmWithRemember + formatAnalysis
│   ├── i18n.ts           ← locale detection + bilingual strings (zh/en)
│   └── logger.ts         ← Logger (file + stderr)
└── dist/
    └── index.js          ← bundled output (bun build, ~44KB)
```

### Runtime artifacts

```
~/.omp/agent/smart-approve.json          — config (user-editable)
~/.omp/agent/smart-approve-allow.json    — permanent allow-list (auto-maintained)
~/.omp/logs/smart-approve.log            — diagnostic log
```

## License

MIT
