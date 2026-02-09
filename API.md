# AgentCI API Reference

This document covers the programmatic APIs for integrating AgentCI into your applications.

## Node.js: CLI Recording

The primary Node.js interface is the `--require` hook. No code changes needed:

```bash
node --require agentci/dist/recorder/register.js your_agent.js
```

Or via the CLI wrapper:

```bash
agentci record -- node your_agent.js
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AGENTCI_RUN_DIR` | Yes | Directory for this run's trace output |
| `AGENTCI_RUN_ID` | Yes | Unique identifier for this run |
| `AGENTCI_WORKSPACE_ROOT` | Yes | Root directory of the workspace |
| `AGENTCI_VERSION` | No | AgentCI version string |
| `AGENTCI_DEBUG` | No | Set to `1` to enable debug logging to stderr |

These are set automatically when using `agentci record`.

## Node.js: OpenClaw Adapter

For framework-level integration (e.g., recording tool calls from an LLM framework):

```typescript
import { emitToolCall, emitToolResult } from 'agentci/dist/adapters/openclaw';

// Record a tool invocation
emitToolCall('read_file', { path: './src/index.ts' });

// Record the tool's result
emitToolResult('read_file', { content: '...' });
```

### `emitToolCall(name, input, runId?)`

Records a tool call event to the active trace.

| Parameter | Type | Description |
|---|---|---|
| `name` | `string` | Tool name (e.g., `"read_file"`, `"web_search"`) |
| `input` | `unknown` | Tool input parameters |
| `runId` | `string?` | Optional run ID override (defaults to `AGENTCI_RUN_ID`) |

### `emitToolResult(name, output, runId?)`

Records a tool result event to the active trace.

| Parameter | Type | Description |
|---|---|---|
| `name` | `string` | Tool name (must match the corresponding `emitToolCall`) |
| `output` | `unknown` | Tool output/result |
| `runId` | `string?` | Optional run ID override (defaults to `AGENTCI_RUN_ID`) |

## Python: Recording API

```python
from agentci_recorder import start_recording, stop_recording

# Start recording
ctx = start_recording(
    run_dir=".agentci/runs/my-run",
    run_id="my-run",
    workspace_root="."
)

# ... your agent code runs here ...

# Stop recording and finalize the trace
stop_recording(ctx)
```

### `start_recording(run_dir, run_id, workspace_root)`

Begins recording side-effects. Patches stdlib modules.

| Parameter | Type | Description |
|---|---|---|
| `run_dir` | `str` | Directory for this run's output |
| `run_id` | `str` | Unique run identifier |
| `workspace_root` | `str` | Root directory of the workspace |

**Returns:** A context object to pass to `stop_recording()`.

### `stop_recording(ctx)`

Stops recording, restores original stdlib functions, and finalizes the trace file.

| Parameter | Type | Description |
|---|---|---|
| `ctx` | `RecordingContext` | Context returned by `start_recording()` |

## Trace Format

AgentCI writes [JSONL](https://jsonlines.org/) — one JSON object per line. Each event:

```json
{
  "id": "evt_abc123",
  "timestamp": 1707300000000,
  "run_id": "run-xyz",
  "type": "effect",
  "data": {
    "category": "fs_write",
    "kind": "observed",
    "fs": {
      "path_requested": "./src/index.ts",
      "path_resolved": "/home/user/project/src/index.ts",
      "is_workspace_local": true
    }
  }
}
```

### Event Types

| Type | Description |
|---|---|
| `lifecycle` | Run start/stop/error events |
| `effect` | Observed side-effect (fs, network, exec, sensitive access) |
| `tool_call` | Declared tool invocation (from OpenClaw adapter) |
| `tool_result` | Declared tool result (from OpenClaw adapter) |

### Effect Categories

| Category | Description |
|---|---|
| `fs_write` | File creation, modification, or rename |
| `fs_read` | File read (external to workspace) |
| `fs_delete` | File or directory deletion |
| `net_outbound` | HTTP/HTTPS request |
| `exec` | Child process execution |
| `sensitive_access` | Environment variable or sensitive file access |

## Effect Signature

The `agentci summarize` command produces a JSON signature:

```json
{
  "meta": {
    "signature_version": "1.0",
    "agentci_version": "0.1.0",
    "platform": "darwin-arm64",
    "adapter": "node-hook",
    "scenario_id": "default",
    "node_version": "v20.14.0"
  },
  "effects": {
    "fs_writes": ["workspace/src/index.ts", "workspace/package.json"],
    "fs_reads_external": [],
    "fs_deletes": [],
    "net_etld_plus_1": ["openai.com"],
    "net_hosts": ["api.openai.com"],
    "exec_commands": ["git", "npm"],
    "exec_argv": ["[\"git\",\"status\"]", "[\"npm\",\"install\"]"],
    "sensitive_keys_accessed": ["OPENAI_API_KEY"]
  }
}
```

## Policy Configuration

Policy is defined in `.agentci/config.yaml`. See the [README](README.md#policy-configuration) for the full schema.

### Policy Findings

The `agentci diff` and `agentci evaluate` commands return findings:

```json
{
  "severity": "BLOCK",
  "category": "network",
  "message": "Host 'evil.com' not allowed by policy.network.allow_etld_plus_1",
  "suggestion": "Add 'evil.com' to policy.network.allow_etld_plus_1 if intended"
}
```

| Severity | Exit Code | Description |
|---|---|---|
| `INFO` | 0 | New behavior, noted |
| `WARN` | 0 | Review recommended |
| `BLOCK` | 1 | Policy violation |

## Integrity Verification

```bash
# Verify a trace hasn't been tampered with
agentci verify .agentci/runs/<run_id>/trace.jsonl
```

Uses HMAC-SHA256 with the project secret (`.agentci/secret`) to verify trace integrity. Returns exit code 0 if valid, 1 if invalid or missing checksum.
