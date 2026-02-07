"""Main recorder entry point for the Python recorder."""

from __future__ import annotations

import atexit
import os
import platform
import sys
import time
from typing import Any

from agentci_recorder.logger import logger
from agentci_recorder.types import make_event
from agentci_recorder.writer import TraceWriter

_active_ctx: dict[str, Any] | None = None


def _load_config_block_env() -> list[str]:
    """Best-effort load of block_env from config."""
    config_path = os.environ.get("AGENTCI_CONFIG_PATH")
    if not config_path or not os.path.isfile(config_path):
        return ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"]
    try:
        import yaml  # optional dep

        with open(config_path, "r") as f:
            parsed = yaml.safe_load(f)
        return parsed.get("policy", {}).get("sensitive", {}).get("block_env", [])
    except Exception as e:
        logger.debug(f"Failed to load config: {e}")
        return ["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"]


def start_recording(
    run_dir: str | None = None,
    run_id: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Start recording side-effects. Returns the recorder context."""
    global _active_ctx

    run_dir = run_dir or os.environ.get("AGENTCI_RUN_DIR")
    if not run_dir:
        raise ValueError("run_dir is required (or set AGENTCI_RUN_DIR)")

    run_id = run_id or os.environ.get("AGENTCI_RUN_ID", os.path.basename(run_dir))
    workspace_root = workspace_root or os.environ.get("AGENTCI_WORKSPACE_ROOT", os.getcwd())

    trace_path = os.path.join(run_dir, "trace.jsonl")
    writer = TraceWriter(trace_path)

    ctx: dict[str, Any] = {
        "run_id": run_id,
        "run_dir": run_dir,
        "workspace_root": workspace_root,
        "writer": writer,
        "state": {"bypass": False},
        "started_at": time.time() * 1000,
    }
    _active_ctx = ctx

    writer.write(
        make_event(
            run_id,
            "lifecycle",
            {"stage": "start"},
            {
                "python_version": sys.version,
                "platform": f"{sys.platform}-{platform.machine()}",
                "recorder": "python",
            },
        )
    )

    from agentci_recorder.patches.filesystem import patch_filesystem
    from agentci_recorder.patches.network import patch_network
    from agentci_recorder.patches.subprocess_patch import patch_subprocess
    from agentci_recorder.patches.env_sensitive import patch_env_sensitive

    try:
        patch_filesystem(ctx)
        logger.debug("Patched filesystem operations")
    except Exception as e:
        logger.debug(f"Failed to patch filesystem: {e}")

    try:
        patch_network(ctx)
        logger.debug("Patched network operations")
    except Exception as e:
        logger.debug(f"Failed to patch network: {e}")

    try:
        patch_subprocess(ctx)
        logger.debug("Patched subprocess operations")
    except Exception as e:
        logger.debug(f"Failed to patch subprocess: {e}")

    try:
        blocked_env = _load_config_block_env()
        patch_env_sensitive(ctx, blocked_env)
        logger.debug(f"Patched env sensitive access ({len(blocked_env)} keys)")
    except Exception as e:
        logger.debug(f"Failed to patch env sensitive: {e}")

    atexit.register(_on_exit, ctx)
    logger.debug(f"Recording started: run_id={run_id}, trace={trace_path}")

    return ctx


def stop_recording(ctx: dict[str, Any] | None = None) -> None:
    """Stop recording and flush remaining events."""
    global _active_ctx
    ctx = ctx or _active_ctx
    if not ctx:
        return

    from agentci_recorder.patches.filesystem import unpatch_filesystem
    from agentci_recorder.patches.network import unpatch_network
    from agentci_recorder.patches.subprocess_patch import unpatch_subprocess
    from agentci_recorder.patches.env_sensitive import unpatch_env_sensitive

    duration = time.time() * 1000 - ctx["started_at"]
    ctx["writer"].write(
        make_event(ctx["run_id"], "lifecycle", {"stage": "stop", "duration_ms": duration})
    )

    unpatch_filesystem()
    unpatch_network()
    unpatch_subprocess()
    unpatch_env_sensitive()

    ctx["writer"].close()
    _active_ctx = None
    logger.debug("Recording stopped")


def _on_exit(ctx: dict[str, Any]) -> None:
    try:
        stop_recording(ctx)
    except Exception:
        pass
