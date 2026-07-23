# smart-approve

A high-risk-only approval hook with LLM risk analysis, behavior detection, protected-path interception, and decision memory. Compatible with both **oh-my-pi (OMP)** and upstream **pi-agent**.

Safe commands pass through with **zero interruption**. When a dangerous behavior is detected or a protected path is hit, the hook invokes the `smol` model — with full session context — to produce a structured risk assessment, then shows a three-way confirmation dialog. In headless (subagent) contexts, dangerous operations are blocked outright.

## How it works

```
LLM calls bash / write / edit
       │
   allow-list hit (session or permanent)? ── yes → pass through
       │ no
   ├─ bash: analyzeCommand() — argument parsing + regex secondary net
   │   ├─ no behaviors → pass through
   │   ├─ hard-block behavior (rm -rf /, fork bomb, curl|sh…) → block always
   │   └─ dangerous behavior → needs review ↓
   │
   ├─ write/edit: isProtectedPath() — glob + symlink-aware
   │   ├─ not protected → pass through
   │   └─ protected → needs review ↓
   │
   ├─ ctx.hasUI === false (headless subagent) → block
       │
       └─ has UI:
          setStatus("analyzing…")
          gatherSessionContext() — original user task + recent agent plan
          detectHost(): omp → pi → null;  <host> -p --model @smol (≤8s, capped below the handler's 30s budget)
              success → dialog shows risk / summary / detail / recommendation
              failure → degrades to rule-only confirmation
          ctx.ui.select(title, [session allow, permanent allow, deny])
              session   → in-memory Set (cleared on restart)
              permanent → persisted to JSON file
              deny      → block
```

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

Intercepts `write`/`edit` tool calls and matches the target path against glob patterns:

- `.env`, `.env.*` (`.env.example` explicitly allowed)
- `**/.ssh/**`, `**/.kube/config`, `**/.aws/credentials`
- `**/.git-credentials`, `**/.netrc`, `**/.npmrc`, `**/.pypirc`
- `**/id_rsa`, `**/id_ed25519`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.kdbx`
- `**/auth.json`, `**/.config/gh/hosts.yml`, `**/.config/gcloud/**`

Matching is **symlink-aware**: resolves `realpath` before matching, so a symlink alias can't evade a deny.

### 3. Decision memory

The confirmation dialog offers three choices:

| Option | Storage | Lifetime |
|---|---|---|
| Allow for this session | In-memory `Set<string>` | Cleared on restart |
| Always allow | `~/.omp/agent/smart-approve-allow.json` | Persists across restarts |
| Deny | — | Blocks the command |

Keys are scoped to `tool + normalized-content + cwd`, so the same command in a different project still triggers review. When the UI doesn't support `select`, it degrades to a simple `confirm` (two-way).

### 4. Persistent configuration with defaults

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
  "contextMaxChars": 3000
}
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch |
| `protectedPaths` | 20+ built-in patterns | Glob patterns for write/edit interception; `!` prefix negates |
| `llmAnalysis` | `true` | Whether to invoke the `smol` model for risk analysis; `false` = rule-only confirmation |
| `rememberDecisions` | `true` | Whether to offer session/permanent remember options in the dialog |
| `contextMaxChars` | `3000` | Max chars of session context to feed the LLM |

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

### 7. OMP + pi dual compatibility with graceful degradation

| Aspect | Implementation |
|---|---|
| Dual manifest | `package.json` declares both `omp.extensions` and `pi.extensions` |
| Host detection | `detectHost()` probes PATH for `omp` → `pi`, cached per process |
| LLM invocation | `omp -p` or `pi -p`, flags shared by both |
| Fallback chain | `omp` fails → `pi` fails → rule-only confirmation (no LLM) |
| Headless | `ctx.hasUI === false` blocks all dangerous operations immediately |
| Bilingual | zh/en, auto-adapts to locale (`LC_ALL` > `LC_MESSAGES` > `LANG` > macOS `AppleLocale`) |

## Install

`package.json` declares both `omp.extensions` and `pi.extensions`, so the same package loads on either runtime. Pick the method that fits:

**Option A — drop into the extensions directory:**

```sh
# OMP
cp -r smart-approve ~/.omp/agent/extensions/smart-approve
# pi-agent
cp -r smart-approve ~/.pi/agent/extensions/smart-approve
```

Restart the host. The hook is active for all sessions.

**Option B — point the `extensions` setting at it:**

```yaml
# ~/.omp/agent/config.yml   (or ~/.pi/agent/config.yml for pi-agent)
extensions:
  - /path/to/smart-approve
```

**Option C — load once via CLI flag:**

```sh
omp --extension ./smart-approve      # OMP
pi  --extension ./smart-approve      # pi-agent
```

## Required configuration

Set `tools.approvalMode: yolo` so safe commands auto-approve and pass through. This hook then acts as the **sole gate** for dangerous commands:

```yaml
# ~/.omp/agent/config.yml   (or ~/.pi/agent/config.yml for pi-agent)
tools:
  approvalMode: yolo
extensions:
  - /path/to/smart-approve
```

Without `yolo`, the host's built-in approval already prompts for `exec`-tier tools (including `bash`), making this hook redundant for interactive sessions — though its headless-block behavior still applies to subagents.

Restart the host after installing or editing.

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
| `pi.on("tool_call", handler)` | Intercept `bash`, `write`, `edit` calls |
| `event.toolName`, `event.input.command` / `event.input.path` | Read tool name and input |
| `ctx.hasUI` | Detect headless/subagent context |
| `ctx.sessionManager.getBranch()` / `getEntries()` | Gather session context for LLM review |
| `ctx.ui.setStatus(id, text)` | Show "analyzing…" status |
| `ctx.ui.confirm(title, body)` | Confirmation dialog (fallback when `select` unavailable) |
| `ctx.ui.select(title, choices)` | Three-way choice: session allow / permanent allow / deny |
| `pi.exec(bin, args, opts)` | Spawn `<host> -p` (`omp` or `pi`) for LLM risk analysis |
| `return { block: true, reason }` | Block contract: `reason` is sent to the LLM |

## Compatibility — OMP and pi-agent

The extension contract (`ExtensionAPI`, `tool_call` event, `ctx.ui.confirm`/`select`, `ctx.hasUI`, `pi.exec`) is shared between OMP and upstream pi-agent. The `package.json` therefore declares both `omp.extensions` and `pi.extensions` manifest keys.

**This extension works on both OMP and pi-agent.** The LLM risk-analysis step auto-detects the host binary at runtime:

| Concern | Status | Detail |
|---|---|---|
| Extension factory + `tool_call` interception | Portable | Standard `ExtensionAPI` surface; works on pi-agent |
| `ctx.ui.confirm` / `select` / `setStatus` / `hasUI` | Portable | Same `ExtensionUIContext` interface on both |
| Behavior detection, protected paths, decision memory, i18n | Portable | Pure TS, no host coupling |
| **Session context gathering** | Best-effort | Uses `ctx.sessionManager.getBranch()` / `getEntries()`. Falls back to `null` (no context) if unavailable — LLM review still works |
| **Host binary detection** | Portable | `detectHost()` probes PATH for `omp` first, then `pi`. Cached for process lifetime |
| **One-shot model invocation** | Portable | `runOneShotModel()` uses flags shared by both (`-p --no-tools --no-session --no-lsp --no-extensions --no-skills --no-rules --no-title --model @smol`) |
| **Fallback chain** | Portable | `omp` absent or fails → retries `pi` → both fail returns `null` → rule-only confirmation |

**On pi-agent (only `pi` on PATH):** `detectHost()` returns `"pi"`; the smol model is invoked via `pi -p`. Full LLM risk analysis works. Only when neither binary is found does the hook degrade to rule-only confirmation.

**On a host with neither binary:** LLM analysis is skipped (returns `null`); core safety (behavior detection, protected path matching, blocking, confirmation dialog) still works — the risk/summary/detail/recommend fields in the dialog are simply absent.

## Comparison with marketplace alternatives

| Dimension | smart-approve | pi-auto-reviewer | @firstpick/safety-guard |
|---|---|---|---|
| Host compatibility | OMP + pi dual | pi only | pi only |
| LLM analysis | smol structured JSON display | ALLOW/BLOCK decision | None |
| Behavior detection | Argument parsing + regex net | Argument parsing + regex | Regex only |
| write/edit interception | Yes (symlink-aware) | No | Yes |
| Decision memory | Session + permanent | None | Session + permanent |
| Session context | Yes (injection-guarded) | Yes | No |
| Bilingual | zh/en | No | No |
| Fallback chain | omp→pi→rule confirmation | pi→fail block | Rule confirmation |

## Project layout

```
smart-approve/
├── README.md        ← this file
├── package.json     ← omp.extensions / pi.extensions manifest (v2.0.0)
├── LICENSE          ← MIT
└── index.ts         ← full source: types + behavior detection + regex rules +
                        protected paths + config + decision memory +
                        session context + LLM invocation + hook entry
```

### Runtime artifacts

```
~/.omp/agent/smart-approve.json          — config (user-editable)
~/.omp/agent/smart-approve-allow.json    — permanent allow-list (auto-maintained)
```

## License

MIT
