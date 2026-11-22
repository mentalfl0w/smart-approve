# smart-approve

An approval gate for **oh-my-pi (OMP)** and upstream **pi-agent**: behavior detection + model risk analysis review dangerous operations. Interactive mode shows the model's recommendation and lets the user decide; auto mode acts only on a valid model verdict. Compatible with both hosts.

Covered execution surfaces:

| Tool | Mechanism | Dangerous-op handling |
|---|---|---|
| `bash` | OMP: same-name wrapper with native schema; Pi: `tool_call` gate | command analysis + model review + user decision or valid auto verdict |
| `eval` | OMP: same-name wrapper with native schema; Pi: `tool_call` gate when present | static subprocess, host-tool invocation, and protected-file-write analysis + model review |
| `write` / `edit` / `apply_patch` / `ast_edit` | `tool_call` target matching | system-sensitive files/devices hard-block; configured protected paths enter the same review flow |
| `write proc://<name>` (OMP) | `tool_call` check for tracked interactive services | shell input always gated; Python/JavaScript also gated when Eval coverage is enabled; reviewed by the same flow |

Operations with nothing flagged for review pass through with **zero interruption**. OMP's same-name Bash/Eval wrappers analyze the effective parameters and delegate to the native tools, so native background, PTY, service, kernel, cancellation, and result behavior stays intact.

Pi keeps its native tools and runs the same authorization pipeline from `tool_call`. Load Smart Approve after extensions that rewrite Bash/Eval inputs. Protected paths and OMP proc stdin also use `tool_call`, subject to the host's event-handler limits.

In OMP, Bash's native schema carries `async`, `pty`, `name`, and `ready`; Smart Approve does not rebuild or filter those fields.

## How it works

```
LLM calls bash / eval / write / edit / …
       │
   ToolGate / protected-path review — shared approval flow
       ├─ hard-block (high-risk launches such as curl/ssh/sudo,
       │  interpreter -c/-e, rm -rf, sensitive working dirs, fork bomb,
       │  curl|sh, eval subprocess + destructive payload…) → block always
       ├─ nothing flagged for review → execute (zero interruption)
       └─ reviewable operation
              ├─ remembered session/permanent decision → execute
              ├─ no UI?
              │    ├─ interactive → block
              │    └─ auto without autoInHeadless → block
              │
              ├─ model analysis (native classifier/judge or chat RPC)
              │
              ├─ auto mode
              │    ├─ valid verdict → allow or block by policy
              │    └─ no valid verdict → UI asks the user; no UI blocks
              └─ interactive mode
                   └─ dialog shows the model analysis; user decides
                      (a missing verdict is shown as such)
```

On Pi, the hook authorizes the current mutable input and then returns control to the native tool; it does not recursively call `executeTool()`.
Hard-block always wins — no allow-list entry, model verdict, or mode can override it.


## Modes and runtime switching

Two approval modes:

| Mode | Dangerous operations |
|---|---|
| `interactive` (default) | Model analysis is shown in a dialog; you choose session-allow / permanent-allow / deny. A missing verdict is shown in the dialog; the decision still belongs to you |
| `auto` | A valid model verdict decides: block or execute. No dialogs for automatic decisions (non-blocking notifications only); without a valid verdict, a UI session asks you and a headless session blocks |

Configured protected-path writes go through the same flow: model analysis first, then the interactive dialog or a valid auto verdict. Matching a protected path is not by itself a mandatory human prompt. Recognized high-risk process launches, recursive force deletes, sensitive working directories, writes to system-sensitive files/devices, and system account-file references in Bash commands or spawned Eval arguments are hard-blocked.

Headless/subagent sessions have no human to ask. Interactive mode blocks reviewable operations. Auto mode uses valid model verdicts only when `autoInHeadless` is enabled; with no valid verdict — or when `autoInHeadless` is disabled — the operation is blocked.

Switch at runtime from the TUI (or RPC client) — no restart needed, and the choice persists:

```
/smart-approve              # toggle interactive <-> auto
/smart-approve auto         # switch to auto
/smart-approve interactive  # switch to interactive
/smart-approve status       # show mode, thresholds, coverage
```

`/smart-approve status` reports `proc-input=tracked` for shell/Python/JavaScript, `shell-only` when Eval coverage is disabled, and `false` when the host exposes no tracked `write proc://` path.

The current mode is also shown as a persistent status-bar chip. The command writes only the changed keys back to `smart-approve.json` — every other user-edited field is preserved.

Auto-mode decision rules:

- A valid model verdict is required for an automatic decision: a parseable `risk` and/or `recommend`. `recommend: "deny"` blocks; `risk` at or above `autoBlockRisk` blocks; `risk=high` but `recommend=allow` blocks (the stricter signal wins — command text is untrusted input).
- No valid verdict (model chain failure, invalid answer, timeout, cancellation, or `llmAnalysis: false`): with a UI the user is asked; without a UI the operation is blocked. There is no regex fallback and no automatic allow.
- Auto-mode approvals are **not** written to the allow-list (model verdicts can change; remembered approvals should stay human decisions).
- Force-push to `main`/`master`/`production`/`prod`/`release`/`trunk` is a reviewed behavior, not a silent regex block. Hard-block rules always win.

## Architecture

Object-oriented, dependency-inverted; every concern is a class:

```
SmartApprove (orchestrator)
 ├─ ConfigStore          — config load + runtime update + selective write-back
 ├─ ModeManager          — runtime mode switching + status
 ├─ AllowList            — session + permanent decision memory
 ├─ AutoDecisionPolicy   — pure auto-mode verdict rules (thresholds; no fallback verdict)
 ├─ ApprovalFlow         — shared allow-list → model → user/auto decision flow
 ├─ ToolGate (abstract, template method) — hard-block + safe pass-through + delegation
 │    ├─ BashToolGate    — command analysis, cd-prefix cwd, native delegation
 │    └─ EvalToolGate    — code analysis (subprocess intent), native delegation
 ├─ EvalCodeBehaviorAnalyzer — static process and file-write intent checks
 └─ ProcInputGuard           — tracked OMP interactive service stdin
```

`ToolGate` defines the invariant gate flow (hard-block → safe pass-through → `ApprovalFlow` → delegate). `ApprovalFlow` owns remembered decisions, the headless policy, model analysis, the interactive dialog, and auto-mode decisions; protected-path writes use it directly. Each concrete gate implements three hooks — `analyze()` / `buildKey()` / `delegate()` — plus its schema and subject extraction. Adding a new covered tool means adding one subclass, not touching the pipeline. Collaborators are injected as narrow interfaces (`AllowListLike`, `ModelInvokerLike`, `LoggerLike`), so the branch matrix is unit-testable without a running host.

## Model risk analysis: chat RPC and native decisions

Chat models keep using one persistent `omp --mode rpc` child per session:

- **One process, many prompts** — extension loading and process startup are paid once per host session.
- **Per-attempt timeout and fallback** — each chat attempt is bounded by `analysisTimeoutMs`; the configured model is tried before `@tiny` → `@smol` → `@default`.
- **Interruption and lifecycle** — the tool's `AbortSignal` cancels the active RPC prompt; the child is closed on `session_shutdown` and reaped after `rpcIdleTimeoutMs`.
- **Quota waits (OMP only)** — the RPC child receives a private `--config` overlay with `retry.waitForUsageReset: false`, so it does not wait for the quota reset window. The user's global config remains unchanged; Pi receives no OMP-specific option.

Registered native decision models bypass chat RPC. Pi uses `ctx.modelRegistry.classify()` for registered classifier models. OMP uses its model registry, credentials, resolved headers, and `@oh-my-pi/pi-ai` `createNativeJudge()` when those APIs are available (OMP 18.10+). Use an exact `provider/model-id` selector so the adapter can identify the model unambiguously.

Both native APIs receive the session context, detected behavior labels, and the exact command or code as untrusted evidence. They return typed choices for risk (`low`/`medium`/`high`) and recommendation (`allow`/`deny`); auto mode passes valid results through `AutoDecisionPolicy`. Native results do not include chat summaries or details.

For example, OMP 18.10+ can use `openrouter/openai/gpt-6-luna-decisions`. Pi requires a registered classifier model, such as `openai/gpt-6-luna` with `OPENAI_API_KEY` or OpenRouter's TypeSafe Jev classifier. Use the exact `provider/model-id` exposed by that host; Pi's current OpenRouter classifier catalog does not list the OpenAI Decisions model.

If a selected native model is unavailable, returns invalid answers, times out, or is cancelled, analysis returns no verdict; it is not silently sent through a different chat model. In interactive mode the dialog says the model has no usable verdict and the user still decides. In auto mode, a UI session asks the user; without a UI the operation is blocked. `autoFallback` no longer changes this.

The configured `analysisTimeoutMs` bounds each chat attempt and the complete native judgment attempt. `0` disables the plugin deadline; provider-level limits still apply.

## Features

### 1. Behavior-based detection (bash)

Matches executable names, parsed arguments, and filesystem targets instead of searching arbitrary command text. Git messages, grep patterns, quoted output, and comments do not become dangerous commands merely because they contain a risk keyword.

| Command | Behavior detected | How |
|---|---|---|
| `git push origin +main` | force-push | `+`refspec, not just `--force` |
| `git push -f origin main` | force-push to protected branch | reviewed behavior (branch-aware) |
| `git branch -d feature` | branch-delete | every local delete needs review: `-d` checks the branch's configured upstream, not `HEAD`, so `-c branch.<name>.remote`/`.merge` can make it discard commits `HEAD` cannot reach |
| `git branch -D feature` | branch-delete | forced delete (`-D`, or `-d`/`--delete` with `-f`/`--force`) |
| `git branch -r -d origin/feature` | branch-delete-remote | remote-tracking refs get their own label |
| `git clean -fd` | git-clean | `--dry-run` excluded |
| `git reset --hard` | hard-reset | `--hard` flag |
| `git worktree remove` | worktree-remove | subcommand parsing |

Command-specific checks preserve destructive Git, container, and filesystem rules. Narrow shell-syntax checks cover fork bombs and code piped to an interpreter; `$(...)`, backtick, and process-substitution bodies are analyzed separately as executable code.

### 2. eval code analysis

`EvalCodeBehaviorAnalyzer` scrubs comments before matching and removes string literals only for spawn-API detection; embedded command text is then inspected for launch and destructive-payload patterns:

Static analysis decides what evidence to hand the model. When a target cannot be determined statically — a computed path, an unresolved working directory, `%run`/`%load`, or dynamic MCP dispatch — the cell is still reviewed; it is not auto-approved or skipped. Without a valid model verdict, a UI session asks the user and a headless session blocks.

- **JS/Bun**: ``Bun.$`…` ``, `Bun.spawn`, `Bun.spawnSync`, `Bun.shell`, `child_process` imports, and Node `exec`/`spawn` APIs
- **Python**: `subprocess` (including `run`, `Popen`, `check_call`, and `check_output`), `asyncio.create_subprocess_*`, `os.system`/`os.popen`, `os.exec*`/`os.spawn*`, `os.fork`/`os.forkpty`, `os.posix_spawn*`, and `multiprocessing.Process` (including bare `Process` when multiprocessing is imported)
- Literal executable arguments to `os.exec*`/`os.spawn*`/`os.posix_spawn*` are parsed for launch-head and interpreter-flag checks; computed executable targets remain a static-analysis limit.
- Launch-head and interpreter-flag classification reuses the Bash command analyzer, including wrapper/quoting semantics; dangerous-argument matching remains Eval's separate joined-argument rule set.
- When code shows actual process-spawn intent, launch executables and interpreter inline flags are checked on the parsed command head, while dangerous arguments are checked across the joined argument stream: high-risk executables (`osascript`, `sudo`, `ssh`, `scp`, `nc`/`netcat`/`ncat`, `socat`, `telnet`, `openssl`, `curl`, `wget`), interpreters with `-c`/`-e`/`-i`/`--eval`/`--command`, `rm -rf` variants, `chmod`/`chown`, `dd ... of=...`, and `/etc/passwd`/`/etc/shadow`/`/etc/sudoers` references hard-block. A safe executable with a high-risk-looking argument, such as `Bun.spawn(["echo", "ssh"])`, stays reviewable.
- Python cells: `!cmd` and `var = !cmd` shell escapes plus `%%bash` count as spawn intent; their literal shell text (with backslash continuations folded as the runner does) goes through the same launch-head, dangerous-argument, and destructive-payload checks. `%%writefile` targets enter Eval write-path checks and its body is treated as file content, not shell text. `%cd` targets enter cwd checks in source order with `chdir`.
- `%run` and `%load` execute external file source that cannot be inspected statically; they are routed to model review instead of claiming static coverage, and no remembered decision is offered because the file can change.
- Literal `process.chdir`/`os.chdir`/`Dir.chdir`/`%cd` targets are resolved against the effective base; a target inside a sensitive system directory hard-blocks unless the session root contains it (the legacy outside-session exception). Lexical and canonical candidates cover symlinked `~/.ssh`/`~/.gnupg`. Computed chdir targets are not resolved; relative writes after a dynamic working directory require review, and such a cell does not offer a remembered decision.
- A leading `cd <path>` inside `!cmd`/`%%bash` is resolved against the effective base cwd; sensitive targets hard-block. Unresolved expansion or a target that is not an existing directory leaves the shell cwd unknown and routes later relative operations to review; no remembered decision is offered. Later absolute sensitive targets are still checked.
- Destructive payloads combined with spawn intent remain hard-blocked. A plain spawn such as `Bun.spawn(["ls"])` stays reviewable.
- OMP package-manager magic cells (`%pip install`, `%bun add`) count as spawn intent and stay reviewable; their package specifiers are not scanned as shell commands.
- Eval approvals offer session-allow only. OMP native kernel state, output truncation, cancellation, and cell results remain with the native Eval tool.

### 3. Process-launch behavior analysis

The Bash analyzer hard-blocks these launch shapes — no LLM review, no allow-list override:

- high-risk executables (`osascript`, `sudo`, `ssh`, `scp`, `nc`/`netcat`/`ncat`, `socat`, `telnet`, `openssl`, `curl`, `wget`);
- interpreters used with `-c`, `-e`, `-i`, `--eval`, or `--command`, while ordinary script launches such as `python3 app.py` and `bun run dev` stay uninterrupted;
- `chmod`/`chown`, `rm -rf` variants (including `rm -r -f` and long forms), `dd ... of=...`, and sensitive working directories outside the session root;
- `mkfs`, shutdown/reboot, raw block-device writes, root deletion, fork bombs, remote fetch-and-execute, and `/etc/passwd`/`/etc/shadow`/`/etc/sudoers` references.

Force-push to a protected branch is reviewed by the model, distinct from these hard blocks. Eval subprocess code (including Python `!` escapes and `%%bash`) receives static process-intent, sensitive-working-directory, and destructive-payload checks. Reviewable operations use the model: interactive mode shows the analysis and lets the user decide; auto mode applies a valid verdict, asks in a UI when there is none, and blocks headless without one.

### 4. Protected paths and Eval file writes

`write`, `edit`, `apply_patch`, and `ast_edit` tool calls are checked against configured glob patterns:

- `.env`, `.env.*` (`.env.example` explicitly allowed)
- `**/.ssh/**`, `**/.kube/config`, `**/.aws/credentials`
- `**/.git-credentials`, `**/.netrc`, `**/.npmrc`, `**/.pypirc`
- `**/id_rsa`, `**/id_ed25519`, `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.kdbx`
- `**/auth.json`, `**/.config/gh/hosts.yml`, `**/.config/gcloud/**`

Matching is **symlink-aware** for file paths. `apply_patch` targets are extracted from patch headers; `edit` uses the host's derived `path`/`paths`; `ast_edit` checks explicit `paths` before its staged preview.

OMP Eval's `write(path, content)` helper writes directly from the retained runtime and does not emit a `write` tool call. Smart Approve checks literal targets for `write`, `Bun.write`, `writeFile`, and `open(..., "w"/"a"/"x")`. A protected literal target goes through the same review flow as file tools: model analysis first, then the interactive dialog or a valid auto verdict. A computed target is also reviewed, not automatically allowed; headless calls without a valid verdict are blocked.
- OMP Eval's `tool.write({ path, content })` object form checks literal filesystem paths against protected-path rules. `agent://`, `xd://`, and `out://` targets are not filesystem paths; `xd://` host-tool invocations are reviewable and go through model analysis. Computed/unknown targets or unsupported object shapes are still reviewed rather than skipped. `proc://` writes are reviewed as unresolved non-file targets, except for the verified Task Group pool-cancel form.
- Eval MCP calls are reviewed before the cell runs: direct `tool.mcp__<name>(...)` (JS and Python, including a static computed member such as `tool["mcp__x"]`), `mcp.evalNamespaces` globals such as `server.method(...)`, and static `tool.write({ path: "xd://mcp__..." })` dispatches. Statically identified MCP calls go through model analysis. Without a valid verdict, a UI session asks the user and a headless session blocks. A tool or namespace member that cannot be resolved statically (`tool[name]`, `server[method]`) or a direct host bridge call (`__omp_call_tool__`, `_bridge_call`) is also routed to review; headless calls without a valid verdict are blocked.

### 5. Decision memory

The interactive dialog offers three choices (two for eval):

| Option | Storage | Lifetime |
|---|---|---|
| Allow for this session | In-memory `Set<string>` | Cleared on restart |
| Always allow | `~/.omp/agent/smart-approve-allow.json` | Persists across restarts |
| Deny | — | Blocks the operation |

Keys are scoped to `tool + normalized-content + cwd`, so the same command in a different project still triggers review. When the UI doesn't support `select`, it degrades to a simple `confirm` (two-way).

Remembered decisions are checked before model analysis; hard blocks always win over them. Operations whose actual target depends on runtime state (an unresolved working directory, a dynamically dispatched host tool, a write target that cannot be resolved statically, or `%run`/`%load` source that can change) are still reviewed but do not offer a remembered decision, and existing remembered entries do not cover them.

### 6. Hard-block behaviors

Always hard-blocked — no LLM review, no dialog, no allow-list override. Bash rules apply to command text; Eval launch/payload rules apply when process-spawn intent is detected.

- High-risk executables (`osascript`, `sudo`, `ssh`, `scp`, `nc`/`netcat`/`ncat`, `socat`, `telnet`, `openssl`, `curl`, `wget`)
- Interpreters invoked with inline-code flags (`-c`, `-e`, `-i`, `--eval`, `--command`)
- Recursive force delete (`rm -rf` variants, including `rm -r -f` and long forms)
- `chmod` / `chown` permission changes and `dd ... of=...` writes
- Sensitive working directories outside the session root (`/etc`, `/usr`, `/var`, `/bin`, `/sbin`, `/boot`, `/Library`, `/System`, `/private`, `~/.ssh`, `~/.gnupg`)
- Delete root path (`rm -rf /`), delete home directory (`rm -rf ~`)
- Fork bombs
- Remote fetch-and-execute (`curl|sh`)
- References to `/etc/passwd`, `/etc/shadow`, or `/etc/sudoers` (Bash always; Eval when process-spawn intent is detected), and writes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts` (Bash, Eval, and file tools)
- Writes to raw block devices (`/dev/sd*`, `/dev/nvme*`, …) through Bash, Eval, and file tools
- Disk format (`mkfs`, `dd` to block device)
- Shutdown / reboot
- eval: subprocess intent (including `!cmd` and `%%bash`) combined with any recognized high-risk launch target, dangerous argument, or destructive payload above
- eval: literal `chdir`/`%cd` or leading shell `cd` in `!cmd`/`%%bash` into a sensitive system directory; relative targets must also resolve outside the session root

Protected-branch force-push is reviewed by the model, not hard-blocked.

### 7. Native execution and result preservation

The extension never executes shell commands or Eval cells itself. OMP's same-name wrappers use `ctx.invokeTool()` to call the native tool and return its result unchanged. Pi keeps the native tool registered; after the `tool_call` gate allows the operation, the host executes it normally.

- **Shell path resolution** — no ENOENT from missing PATH in worker processes
- **PTY support** — interactive commands work when the native tool uses PTY
- **Env hardening** — `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, etc.
- **Output truncation** — head/tail windows with artifact spill
- **Retained eval kernels** — code still sees persistent state, `reset` still works
- **Cross-platform** — no hardcoded binary paths

## Known boundaries (honest scope)

- Detection is static and pattern-based, not a sandbox or complete filesystem interception. Bash parses command positions and common launch wrappers (`env`, `command`, `nohup`, `timeout`, `xargs`, `find -exec`), but shell indirection (variables, aliases, scripts that construct commands) is not interpreted. Eval launch and payload checks require recognized spawn APIs or Python shell magics; `chdir`/`%cd` checks use literal targets and literal leading shell `cd` targets. Obfuscated imports, computed process names, native bindings, and alternate filesystem APIs cannot be fully classified.
- Eval checks the submitted cell, not the full retained kernel state. A helper defined in an earlier cell can call an MCP tool, bind a dynamic dispatcher, perform a process launch, or write without repeating the visible API in the current cell. `%run`/`%load` are routed to review because their source is not inspected, and no remembered decision is offered; retained-kernel state is not introspected, so this is not a sandbox.
- MCP namespace recognition depends on the live host tool inventory exposing `mcpServerName` (OMP does while connected, including when `mcp.evalNamespaces` hides the server's top-level tools). If the inventory is unavailable, direct `tool.mcp__*` still matches the MCP prefix, but a non-prefixed namespace global cannot be attributed; a dynamic `tool[...]` dispatch is still routed to review. Globals that OMP renamed on a collision (for example `github_mcp`) are not reconstructed from the server name.
- Eval MCP detection follows the submitted source text. Exotic indirection such as `globalThis["tool"]`, `getattr(tool, name)`, passing `tool` to a helper, or aliasing a namespace through another object is not classified. The gate is not a sandbox; review the cell rather than relying on a claim of complete MCP coverage.
- Proc-service cwd is inferred from literal `cd`/`chdir` input after a successful `write proc://` result. OMP reports that input was sent, not whether a conditional or failing command changed cwd; indirect changes can desynchronize the inferred path. Unknown cwd is routed to review; without a valid verdict a UI session asks the user and a headless session blocks.
- Eval code runs in a retained kernel, but the host resets the runner working directory to the session cwd before each cell, so a `chdir` does not carry into later cells. Literal `chdir`/`%cd` operations are resolved in source order for the hard-block check; computed targets are not resolved against the live runtime directory. A leading shell `cd` inside `!cmd`/`%%bash` is resolved against the effective base cwd. Same-cell dynamic `chdir` with relative writes remains review-worthy rather than statically classified. This is a gate on each submitted snippet, not live filesystem interception.
- Python `%%writefile` targets are checked, but its body is file content, not shell code. A shell `cd` target that cannot be resolved before execution (for example, a symlink created earlier in the same input) requires review rather than a no-override hard block.
- Bash hard-blocks file operands for `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers`, including reads. Grep/rg patterns, sed/awk programs, and Git messages/search terms count as data.
- Eval hard-blocks those references only when code shows spawn intent. Other system files do not all share that rule.
- OMP TUI `!`/`!!` shell commands (`user_bash`) and RPC `bash` are separate session-level execution paths, not registry `tool_call` invocations. Smart Approve covers model-facing Bash tool calls; these user-owned shell entrypoints are not gated by this extension.
- OMP proc stdin protection covers only interactive shell/Python/JavaScript services started through Smart Approve in the same workspace. When `coverage.eval` is false, only shell input is gated. Other process types, services started before the extension, and detached services after a host restart are not tracked; their stdin passes through unchanged.
- `ast_edit` path protection checks explicit paths. Directory/glob expansion is owned by OMP and is not expanded by this extension; broad scopes can include protected files. The later `xd://resolve` request does not expose its resolved target list.
- OMP's protected-path and proc-stdin guards still run on `tool_call` events; a later extension that rewrites those inputs can change them after Smart Approve's check. Load Smart Approve after any extension that rewrites file or proc inputs. The OMP Bash/Eval wrappers recheck the effective final parameters after tool-call handlers.
- Pi runs `tool_call` handlers in extension load order and mutates `event.input` in place; its Bash/Eval gates are load-order-sensitive. Load Smart Approve after extensions that rewrite Bash/Eval input; a later mutating handler can otherwise change arguments after approval.
- OMP `ctx.invokeTool()` exists only when a same-name native built-in is available. If a host advertises the wrapper but does not provide that public delegate, Smart Approve returns a delegation error rather than using a non-native execution fallback.
- This extension does not shadow top-level MCP tools, `github`, `debug`, `browser`, or `computer`. It covers MCP only when reached from an Eval cell (direct `tool.mcp__*`, MCP namespace globals, static `xd://` device writes); direct calls to those tools outside Eval keep their own host approval policy. `debug` has a native approval prompt available (`tools.approval.debug: prompt`); recommend the same for any other tool you want gated natively.
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

OMP wraps Bash/Eval by name and delegates to their native implementations; Pi keeps its native tools and authorizes them before execution. Restart the host after installing or editing.

## Configuration

Config lives at `~/.omp/agent/smart-approve.json` (or `~/.pi/agent/smart-approve.json` on pi-agent). All fields are optional — defaults apply when missing:

```json
{
  "enabled": true,
  "mode": "interactive",
  "autoBlockRisk": "high",
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

The legacy `coverage.hub` key is ignored. `autoFallback` is a legacy key: it is accepted and preserved for compatibility, but it no longer affects decisions. Without a usable model verdict, a UI session asks the user and a headless session blocks. No configuration migration is required.

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch |
| `mode` | `"interactive"` | `"interactive"` (model recommendation + dialog) or `"auto"` (valid model verdict decides, no dialogs). Switchable at runtime via `/smart-approve` |
| `autoBlockRisk` | `"high"` | Auto mode: a valid model verdict with risk at or above this level blocks (`"high"` or `"medium"`) |
| `autoInHeadless` | `false` | Auto mode in headless/subagent sessions: a valid model verdict may decide. With no valid verdict, the operation is blocked |
| `coverage.eval` | `true` | Enable Eval analysis when the host exposes an Eval tool |
| `protectedPaths` | 20+ built-in patterns | Glob patterns checked for write/edit/apply_patch/ast_edit and literal Eval helper writes. A match enters the normal review flow; system-sensitive files/devices remain hard-blocked even when empty |
| `llmAnalysis` | `true` | Whether to invoke the model for risk analysis; `false` = static rules only. Reviewable operations then have no model verdict: a UI session asks the user and a headless session blocks |
| `rememberDecisions` | `true` | Whether to offer remember options in the dialog |
| `contextMaxChars` | `3000` | Max chars of session context to feed the model |
| `analysisTimeoutMs` | `30000` | Chat: timeout per RPC attempt. Native decision: deadline for the whole analysis, including model-header resolution. `0` disables the plugin timeout; provider limits still apply |
| `rpcIdleTimeoutMs` | `600000` | Idle lifetime of the persistent RPC child in ms; `0` = keep alive until session end |
| `model` | `@tiny` | Chat role alias/provider/id, or a fully qualified registered Pi classifier / OMP native-judgment model |

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
| `pi.registerTool({ name, parameters, execute })` | OMP same-name Bash/Eval wrappers, registered after runtime initialization and using native schemas |
| `pi.getAllTools()` | Runtime capability discovery from `session_start`; action methods are unavailable during factory loading |
| `pi.zod` | Injected zod module for tool parameter schemas |
| `ctx.invokeTool(params, opts)` | OMP same-name native delegation; keeps native Bash/Eval results and lifecycle |
| `child_process.spawn(hostBin, ["--mode", "rpc", ...])` | Persistent RPC child for chat-model risk analysis |
| `ctx.modelRegistry.classify()` | Pi classifier lookup, credentials, and typed classification |
| `@oh-my-pi/pi-ai.createNativeJudge()` | OMP native judgment transport, loaded only when supported |
| `pi.on("tool_call", handler)` | Pi Bash/Eval gates; OMP protected-path/proc-input checks and final input rewrites for native wrappers |
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
│   ├── index.ts          ← SmartApprove orchestrator: wiring + commands + protected-path/proc hooks
│   ├── approval.ts       ← ApprovalFlow (allow-list → model → user/auto decision)
│   ├── gate.ts           ← ToolGate (hard-block + ApprovalFlow + delegation) + dep contracts
│   ├── bash-tool.ts      ← OMP BashToolGate wrapper; Pi uses native tool_call gate
│   ├── eval-tool.ts      ← OMP EvalToolGate wrapper; Pi uses native tool_call gate
│   ├── policy.ts         ← AutoDecisionPolicy (auto-mode verdict rules; no fallback)
│   ├── mode-manager.ts   ← ModeManager (runtime switching + status)
│   ├── behaviors.ts      ← bash behavior catalog (hard/review rules) + git parser
│   ├── eval-analyzer.ts  ← EvalCodeBehaviorAnalyzer (subprocess intent)
│   ├── proc-input-guard.ts ← tracked interactive OMP process stdin
│   ├── types.ts          ← ExtensionAPI, ToolDefinition, DangerAnalysis, …
│   ├── host.ts           ← HostResolver + ModelInvoker (chat/native routing)
│   ├── native-decision-adapter.ts  ← selector + shared timeout/cancellation lifecycle
│   ├── native-decision-protocol.ts ← host-neutral state, questions, and answer mapping
│   ├── omp-native-judge-adapter.ts ← OMP registry/auth + native Judgment API
│   ├── pi-classifier-adapter.ts    ← Pi classifier registry adapter
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
    └── index.js          ← bundled output (OMP AI module stays external)
```

### Runtime artifacts

```
~/.omp/agent/smart-approve.json          — config (user-editable; mode toggles persist here)
~/.omp/agent/smart-approve-allow.json    — permanent allow-list (auto-maintained)
~/.omp/logs/smart-approve.log            — diagnostic log
```

## License

MIT
