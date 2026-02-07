# AgentCI Python Recorder

Record every side-effect your Python agent produces — filesystem, network, subprocess, and sensitive access — in the same trace format as the Node.js recorder.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
# Record a Python agent
agentci-record -- python my_agent.py

# Then use the AgentCI CLI to analyze
agentci summarize .agentci/runs/<run_id>/trace.jsonl
agentci diff .agentci/baseline.json .agentci/runs/<run_id>/signature.json
```

## Programmatic API

```python
from agentci_recorder import start_recording, stop_recording

ctx = start_recording(
    run_dir=".agentci/runs/my-run",
    run_id="my-run",
    workspace_root="."
)

# Your agent code runs here — all side-effects are recorded automatically

stop_recording(ctx)
```

## What Gets Recorded

| Category | Patched APIs |
|---|---|
| **File I/O** | `open()`, `os.remove`, `os.unlink`, `os.rename`, `os.makedirs`, `os.mkdir`, `shutil.rmtree` |
| **Network** | `urllib.request.urlopen`, `http.client.HTTPConnection.request`, `http.client.HTTPSConnection.request` |
| **Subprocess** | `subprocess.Popen`, `subprocess.run` |
| **Sensitive** | `os.environ` reads for configured blocked keys |

Only metadata is recorded (paths, hostnames, command names). File contents, HTTP bodies, and secret values are never captured.

## Debug Logging

```bash
AGENTCI_DEBUG=1 agentci-record -- python my_agent.py
```

## Trace Compatibility

Produces the same JSONL trace format as the Node.js recorder. All AgentCI CLI commands (`summarize`, `diff`, `report`, `verify`) work with Python traces.
