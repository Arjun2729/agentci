# AgentCI

**See exactly what your AI agent did.** Every file written, every HTTP request, every shell command — recorded, diffed, and policy-checked.

```
$ agentci record -- node my_agent.js

Recording... done (247 events in 3.2s)

$ agentci summarize .agentci/runs/latest/trace.jsonl

Effect Signature:
  fs_writes:        12 files (workspace/src/**, workspace/package.json)
  net_outbound:     3 hosts (api.openai.com, registry.npmjs.org, example.com)
  exec_commands:    4 commands (npm, git, node, tsc)
  sensitive_access: 1 key (OPENAI_API_KEY)

$ agentci diff .agentci/baseline.json .agentci/runs/latest/signature.json

  BLOCK  New network host: registry.npmjs.org (not in allow list)
  BLOCK  New exec command: tsc (not in allow list)
  WARN   New file write outside workspace: /tmp/cache.json
  INFO   2 new files in workspace/src/

Exit code: 1 (policy violation)
```

## Why

AI agents write files, call APIs, run shell commands, and access secrets. Today you find out what they did by reading the git diff *after the fact* — if you're lucky.

AgentCI records every side-effect as it happens, produces a stable **Effect Signature** you can diff across runs, and checks it against your policy. Think `strace` for AI agents, with opinions.

**What it is not:** AgentCI does not capture LLM prompts, completions, or internal reasoning. It records *observable actions only* — the things that actually change your system.

## Install

```bash
# Node.js (>= 18.17)
npm install agentci

# Python (>= 3.9)
pip install agentci-recorder
```

## 60-Second Quickstart

```bash
# 1. Create a default policy for your repo
agentci adopt

# 2. Record an agent session
agentci record -- node my_agent.js

# 3. Summarize the trace into an Effect Signature
agentci summarize .agentci/runs/<run_id>/trace.jsonl

# 4. Set it as your baseline (first time only)
cp .agentci/runs/<run_id>/signature.json .agentci/baseline.json

# 5. Record again, diff against baseline
agentci record -- node my_agent.js
agentci summarize .agentci/runs/<new_run_id>/trace.jsonl
agentci diff .agentci/baseline.json .agentci/runs/<new_run_id>/signature.json
```

Exit code `1` means a policy violation was found. Use it in CI to gate agent-generated PRs.

## What Gets Recorded

| Category | Node.js | Python | Examples |
|---|---|---|---|
| **File writes** | `fs.writeFileSync`, `fs.appendFile`, ... | `open(..., 'w')`, `os.rename`, ... | `wrote ./src/index.ts` |
| **File reads** | `fs.readFileSync`, `fs.readFile`, ... | `open(..., 'r')` | `read ~/.aws/credentials` |
| **File deletes** | `fs.unlinkSync`, `fs.rmSync`, ... | `os.remove`, `shutil.rmtree`, ... | `deleted ./temp/cache` |
| **Network** | `http.request`, `https.get`, `fetch` | `urllib`, `http.client` | `GET https → api.openai.com` |
| **Shell commands** | `child_process.spawn/exec/fork` | `subprocess.Popen/run` | `exec: npm install express` |
| **Sensitive access** | `process.env` reads | `os.environ` reads | `accessed OPENAI_API_KEY` |

AgentCI records **metadata only** — file paths, hostnames, command names. It never captures file contents, HTTP bodies, or secret values.

## Policy Configuration

`agentci adopt` generates `.agentci/config.yaml`:

```yaml
version: 1
workspace_root: "."
policy:
  filesystem:
    allow_writes: ["./workspace/**", "./src/**"]
    block_writes: ["/etc/**", "~/**"]
  network:
    allow_etld_plus_1: ["openai.com", "anthropic.com"]
    allow_hosts: ["*.openai.com"]
  exec:
    allow_commands: ["git", "node", "npm", "npx"]
    block_commands: ["rm", "curl", "wget", "ssh"]
  sensitive:
    block_env: ["AWS_SECRET_ACCESS_KEY", "DATABASE_URL"]
    block_file_globs: ["~/.ssh/**", "~/.aws/**"]
```

Policy findings have three severities:
- **INFO** — new behavior, noted but allowed
- **WARN** — potentially concerning, review recommended
- **BLOCK** — policy violation, exit code 1

## Commands

| Command | Description |
|---|---|
| `agentci adopt` | Scan repo, generate `.agentci/config.yaml` with sensible defaults |
| `agentci record -- <cmd>` | Run a command with the recorder, produce `trace.jsonl` |
| `agentci summarize <trace>` | Derive an Effect Signature from a trace |
| `agentci diff <baseline> <current>` | Diff two signatures, evaluate policy, exit 1 on violation |
| `agentci report <baseline> <current>` | Generate a self-contained HTML report |
| `agentci verify <trace>` | Verify trace file integrity (HMAC-SHA256) |
| `agentci serve` | Serve HTML reports locally |
| `agentci dashboard` | Launch the web dashboard |

## Python Recorder

The Python recorder produces the same JSONL trace format, so you use the same CLI for analysis:

```bash
# Record a Python agent
agentci-record -- python my_agent.py

# Or use the API
from agentci_recorder import start_recording, stop_recording

ctx = start_recording(run_dir=".agentci/runs/my-run", run_id="my-run", workspace_root=".")
# ... your agent code ...
stop_recording(ctx)

# Then summarize/diff/report with the same CLI
agentci summarize .agentci/runs/my-run/trace.jsonl
```

## Use in CI

```yaml
# .github/workflows/agent-check.yml
- name: Check agent behavior
  run: |
    agentci diff .agentci/baseline.json .agentci/runs/$RUN_ID/signature.json
    # Fails the job if the agent did something outside policy
```

## Trace Format

AgentCI writes [JSONL](https://jsonlines.org/) — one JSON object per line, append-only, crash-resilient. Each event:

```json
{"id":"evt_01","timestamp":1707300000000,"run_id":"abc123","type":"effect","data":{"category":"fs_write","kind":"observed","fs":{"path_requested":"./src/index.ts","path_resolved":"/home/user/project/src/index.ts","is_workspace_local":true}}}
```

Traces are signed with HMAC-SHA256 on close. Use `agentci verify` to confirm a trace hasn't been modified.

## Architecture

```
your-agent  →  agentci recorder (runtime patches)  →  trace.jsonl
                                                          ↓
                                                    agentci summarize  →  signature.json
                                                                              ↓
                                              baseline.json  →  agentci diff  →  findings + exit code
```

The recorder uses `--require` (Node.js) or stdlib monkey-patching (Python) to intercept side-effects at runtime. No kernel hooks, no eBPF, no containers. Works anywhere Node or Python runs.

## Limitations

- **Subprocess opacity:** If your agent spawns a binary that does its own I/O, AgentCI can't see inside it. It records that the subprocess was launched, but not what it did internally.
- **Native module bypass:** C++ addons that call libc directly bypass the Node.js patches.
- **No bodies:** Network recording captures host/method/protocol only. Request and response bodies are not recorded.
- **Best-effort secrets:** AgentCI records which env vars and sensitive files were *accessed*, never their values.

## Development

```bash
git clone https://github.com/anthropics/agentci.git  # TODO: update URL
cd agentci
npm install
npm run build
npm test

# Run the demo
npm run demo
```

## License

MIT
