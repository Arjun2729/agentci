# AgentCI

![Tests](https://img.shields.io/badge/tests-82%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-71%25_%28core%29-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> **Coverage note:** The 71% figure covers core logic (types, schema, integrity, policy, diff, signature, recorder, writer). Runtime patches (`src/recorder/patches/`) are tested via integration tests in spawned subprocesses and excluded from V8 coverage measurement, which cannot instrument child processes.

**CI guardrails / regression tests for agent side effects.** Every file written, every HTTP request, every shell command — recorded, diffed, and policy-checked.

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

**Also not a sandbox:** AgentCI detects and fails fast on common runtime paths. It is **not** a kernel-level security sandbox.

## Install

```bash
# Node.js (>= 18.17)
npm install agentci

# Python (>= 3.9)
pip install agentci-recorder
```

## 60-Second Quickstart

```bash
# 1. Initialize config + secret
agentci init

# 2. Record an agent session
agentci record -- node my_agent.js

# 3. Summarize the trace into an Effect Signature
agentci summarize .agentci/runs/<run_id>/trace.jsonl

# 4. Create a baseline from that run
agentci baseline create .agentci/runs/<run_id>

# 5. Record again, diff against baseline
agentci record -- node my_agent.js
agentci summarize .agentci/runs/<new_run_id>/trace.jsonl
agentci diff .agentci/baseline.json .agentci/runs/<new_run_id>/signature.json
```

Exit code `1` means a policy violation was found. Use it in CI to gate agent-generated PRs.

Use `agentci record --enforce` to fail immediately on policy violations during execution.

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

`agentci init` generates `.agentci/config.yaml`:

```yaml
version: 1
workspace_root: "."
normalization:
  version: "1.0"
  filesystem:
    collapse_temp: true
    collapse_home: true
    ignore_globs: ["**/.DS_Store", "**/Thumbs.db", "**/.git/**", "**/.idea/**", "**/.vscode/**"]
  network:
    normalize_hosts: true
  exec:
    argv_mode: "hash"
    mask_patterns: []
policy:
  filesystem:
    allow_writes: ["./workspace/**", "./tmp/**"]
    block_writes: ["/etc/**", "~/**"]
    enforce_allowlist: false
  network:
    allow_etld_plus_1: []
    allow_hosts: []
    enforce_allowlist: true
  exec:
    allow_commands: ["git", "ls", "echo", "node", "npm"]
    block_commands: ["rm", "curl", "wget"]
    enforce_allowlist: true
  sensitive:
    block_env: ["AWS_*", "OPENAI_*", "*_TOKEN", "*_KEY", "*_SECRET", "*_PASSWORD"]
    block_file_globs: ["~/.ssh/**", "~/.aws/**", "**/.env*"]
```

Policy findings have three severities:
- **INFO** — new behavior, noted but allowed
- **WARN** — potentially concerning, review recommended
- **BLOCK** — policy violation, exit code 1

## Commands

| Command | Description |
|---|---|
| `agentci init` | Initialize `.agentci/config.yaml` + signing secret |
| `agentci adopt` | Alias for `init` |
| `agentci record -- <cmd>` | Run a command with the recorder, produce `trace.jsonl` |
| `agentci summarize <trace>` | Derive an Effect Signature from a trace |
| `agentci diff <baseline> <current>` | Diff two signatures, evaluate policy, exit 1 on violation |
| `agentci evaluate <signature>` | Evaluate a signature against policy |
| `agentci report <baseline> <current>` | Generate a self-contained HTML report |
| `agentci attest <baseline> <current>` | Generate an attestation JSON for CI |
| `agentci verify <trace>` | Verify trace file integrity (HMAC-SHA256) |
| `agentci serve` | Serve HTML reports locally |
| `agentci dashboard` | Launch the web dashboard |
| `agentci baseline create <trace_or_run_dir>` | Create `.agentci/baseline.json` from a run |
| `agentci baseline approve` | Approve baseline with metadata |
| `agentci baseline status` | Show baseline metadata and digest status |
| `agentci policy list` | List bundled policy packs |
| `agentci policy show <pack>` | Show a policy pack |
| `agentci policy apply <pack>` | Apply a policy pack to config |

Use `--format json` on `diff`, `evaluate`, and `verify` for machine-readable CI output.

## Policy Packs

Bundled packs live in `policy-packs/`. Apply them like this:

```bash
agentci policy list
agentci policy apply no_new_egress
```

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

See `examples/ci/` for GitHub Actions, GitLab CI, CircleCI, and Buildkite templates.

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

## Security Model

AgentCI is an **observability tool, not a sandbox**. It records side-effects for audit and policy enforcement, but it cannot prevent a determined agent from performing actions.

### Threat model

| Threat | Protected? | Notes |
|---|---|---|
| Agent writes to unexpected files | **Detected** | Recorded in trace, flagged by policy |
| Agent calls unexpected APIs | **Detected** | Hostname and method recorded |
| Agent runs blocked shell commands | **Detected** | Flagged as BLOCK by policy |
| Agent accesses sensitive env vars | **Detected** | Access recorded (values never captured) |
| Trace file tampering post-run | **Detected** | HMAC-SHA256 integrity verification |
| Agent bypasses recorder via native addon | **Not detected** | Fundamental limitation of userland patching |
| Agent reads `.agentci/secret` to forge traces | **Mitigated** | Secret file is 0o600; document in `.gitignore` |
| Agent disables recorder at runtime | **Not prevented** | Recorder is co-resident; isolation requires containers |

### Trust assumptions

- The **filesystem** is trusted at recording time — AgentCI does not defend against a pre-compromised host.
- The `.agentci/secret` file must be **owner-readable only** (0o600) and must **never be committed to version control**.
- Trace integrity verification is only as strong as the secret key. Rotate it periodically with `agentci init`.
- The **dashboard is an internal tool** — it has no authentication. Run it behind a reverse proxy or VPN in production.

### Security best practices

1. **Add `.agentci/secret` to `.gitignore`** — this file is your HMAC signing key.
2. **Run the dashboard on localhost or behind a reverse proxy** with authentication (see [Dashboard Deployment](#dashboard-deployment) below).
3. **Set file permissions** on `.agentci/` to restrict access: `chmod 700 .agentci`.
4. **Rotate the secret** periodically by deleting `.agentci/secret` and running `agentci init` again.
5. **Review baseline signatures** before committing them — they define what's "normal" behavior.
6. **Use `agentci verify`** to confirm trace integrity before acting on findings.

### Dashboard Deployment

The AgentCI dashboard has **no built-in authentication**. For production deployments, run it behind a reverse proxy with authentication and rate limiting.

<details>
<summary><strong>nginx + OAuth2 Proxy</strong></summary>

```nginx
server {
    listen 443 ssl;
    server_name agentci.internal.example.com;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=agentci:10m rate=30r/m;

    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
    }

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        limit_req zone=agentci burst=10 nodelay;
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

</details>

<details>
<summary><strong>Caddy</strong></summary>

```
agentci.internal.example.com {
    basicauth / {
        admin $2a$14$... # caddy hash-password
    }
    rate_limit {remote.ip} 30r/m
    reverse_proxy localhost:8788
}
```

</details>

<details>
<summary><strong>Docker with localhost only</strong></summary>

```bash
# Bind to localhost only (simplest option for local development)
docker run -p 127.0.0.1:8788:8788 -v $(pwd)/.agentci:/data/.agentci agentci
```

</details>

> **Note:** The dashboard's built-in rate limiter (100 req/min per IP) provides basic abuse protection, but a reverse proxy should handle rate limiting in production for better performance and flexibility.

## Limitations

- **Subprocess opacity:** If your agent spawns a binary that does its own I/O, AgentCI can't see inside it. It records that the subprocess was launched, but not what it did internally.
- **Native module bypass:** C++ addons that call libc directly bypass the Node.js patches.
- **Env proxy bypass:** Native code using `uv_os_getenv()` or `JSON.stringify(process.env)` may access env vars without triggering the recorder. The proxy intercepts `get`, `has`, and `getOwnPropertyDescriptor` traps, but some access patterns may bypass it.
- **No bodies:** Network recording captures host/method/protocol only. Request and response bodies are not recorded.
- **Best-effort secrets:** AgentCI records which env vars and sensitive files were *accessed*, never their values.
- **No Windows permission enforcement:** On FAT/NTFS filesystems, POSIX file permissions (used for the secret file) may not be enforced.

See `docs/coverage.md` for a full coverage/bypass matrix.

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
