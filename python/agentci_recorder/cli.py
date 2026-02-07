"""CLI entry point for the Python recorder.

Usage:
    agentci-record -- python my_script.py
    python -m agentci_recorder.cli -- python my_script.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time


def main() -> None:
    separator_idx = None
    for i, arg in enumerate(sys.argv[1:], start=1):
        if arg == "--":
            separator_idx = i
            break

    if separator_idx is None or separator_idx + 1 >= len(sys.argv):
        print("Usage: agentci-record -- <command...>", file=sys.stderr)
        sys.exit(1)

    cmd_args = sys.argv[separator_idx + 1 :]
    cwd = os.getcwd()

    run_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
    run_dir = os.path.join(cwd, ".agentci", "runs", run_id)
    os.makedirs(run_dir, exist_ok=True)

    env = {
        **os.environ,
        "AGENTCI_RUN_DIR": run_dir,
        "AGENTCI_RUN_ID": run_id,
        "AGENTCI_WORKSPACE_ROOT": cwd,
        "AGENTCI_VERSION": "0.1.0",
    }

    config_path = os.path.join(cwd, ".agentci", "config.yaml")
    if os.path.isfile(config_path):
        env["AGENTCI_CONFIG_PATH"] = config_path

    # Inject the recorder via PYTHONSTARTUP or sitecustomize
    recorder_bootstrap = os.path.join(os.path.dirname(__file__), "_bootstrap.py")
    env["PYTHONSTARTUP"] = recorder_bootstrap

    result = subprocess.run(cmd_args, env=env)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
