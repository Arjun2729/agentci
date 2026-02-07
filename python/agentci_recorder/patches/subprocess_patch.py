"""Monkey-patches for Python subprocess module."""

from __future__ import annotations

import subprocess
from typing import Any

from agentci_recorder.canonicalize import normalize_command
from agentci_recorder.logger import logger
from agentci_recorder.types import EffectEventData, ExecEffectData, effect_data_to_dict, make_event

_original_popen_init = subprocess.Popen.__init__
_original_run = subprocess.run


def _record_exec(ctx: dict[str, Any], command: str, args: list[str]) -> None:
    try:
        cmd, argv = normalize_command(command, args)
        data = EffectEventData(
            category="exec",
            kind="observed",
            exec=ExecEffectData(command_raw=command, argv_normalized=argv),
        )
        ctx["writer"].write(
            make_event(ctx["run_id"], "effect", effect_data_to_dict(data))
        )
    except Exception as e:
        logger.debug(f"Failed to record exec effect: {e}")


def _extract_command(args_input: Any) -> tuple[str, list[str]]:
    if isinstance(args_input, str):
        return args_input, []
    if isinstance(args_input, (list, tuple)):
        items = [str(a) for a in args_input]
        return items[0] if items else "", items[1:]
    return str(args_input), []


def patch_subprocess(ctx: dict[str, Any]) -> None:
    """Patch subprocess.Popen and subprocess.run."""

    def patched_popen_init(self: Any, args: Any, *pos_args: Any, **kwargs: Any) -> Any:
        if not ctx["state"]["bypass"]:
            cmd, cmd_args = _extract_command(args)
            _record_exec(ctx, cmd, cmd_args)
        return _original_popen_init(self, args, *pos_args, **kwargs)

    def patched_run(args: Any, *pos_args: Any, **kwargs: Any) -> Any:
        if not ctx["state"]["bypass"]:
            cmd, cmd_args = _extract_command(args)
            _record_exec(ctx, cmd, cmd_args)
        return _original_run(args, *pos_args, **kwargs)

    subprocess.Popen.__init__ = patched_popen_init  # type: ignore[assignment]
    subprocess.run = patched_run  # type: ignore[assignment]


def unpatch_subprocess() -> None:
    subprocess.Popen.__init__ = _original_popen_init  # type: ignore[assignment]
    subprocess.run = _original_run  # type: ignore[assignment]
