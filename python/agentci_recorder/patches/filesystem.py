"""Monkey-patches for Python filesystem operations (builtins.open, os, shutil)."""

from __future__ import annotations

import builtins
import fnmatch
import os
import shutil
from typing import Any

from agentci_recorder.canonicalize import resolve_path_best_effort
from agentci_recorder.logger import logger
from agentci_recorder.types import EffectEventData, FsEffectData, effect_data_to_dict, make_event

_original_open = builtins.open
_original_remove = os.remove
_original_unlink = os.unlink
_original_rename = os.rename
_original_makedirs = os.makedirs
_original_mkdir = os.mkdir
_original_rmtree = shutil.rmtree


def _should_skip(resolved_path: str, workspace_root: str) -> bool:
    agentci_root = os.path.join(os.path.abspath(workspace_root), ".agentci")
    return resolved_path.startswith(agentci_root)


def _record_fs(ctx: dict[str, Any], category: str, input_path: str) -> None:
    try:
        resolved = resolve_path_best_effort(input_path, ctx["workspace_root"])
        if _should_skip(resolved.resolved_abs, ctx["workspace_root"]):
            return
        data = EffectEventData(
            category=category,  # type: ignore[arg-type]
            kind="observed",
            fs=FsEffectData(
                path_requested=input_path,
                path_resolved=resolved.resolved_abs,
                is_workspace_local=resolved.is_workspace_local,
            ),
        )
        ctx["writer"].write(
            make_event(ctx["run_id"], "effect", effect_data_to_dict(data))
        )
        if category == "fs_read":
            blocked = ctx.get("block_file_globs", [])
            if _match_blocked_globs(blocked, resolved.resolved_abs):
                sensitive = EffectEventData(
                    category="sensitive_access",
                    kind="observed",
                    sensitive={"type": "file_read", "key_name": resolved.resolved_abs},
                )
                ctx["writer"].write(
                    make_event(ctx["run_id"], "effect", effect_data_to_dict(sensitive))
                )
    except Exception as e:
        logger.debug(f"Failed to record fs effect ({category}): {e}")


def _match_blocked_globs(patterns: list[str], path_value: str) -> bool:
    if not patterns:
        return False
    normalized = os.path.expanduser(path_value).replace("\\", "/")
    for pattern in patterns:
        expanded = os.path.expanduser(pattern).replace("\\", "/")
        if fnmatch.fnmatchcase(normalized, expanded):
            return True
    return False


def patch_filesystem(ctx: dict[str, Any]) -> None:
    """Patch builtins.open, os.remove, os.unlink, os.rename, os.makedirs, os.mkdir, shutil.rmtree."""

    def patched_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if not ctx["state"]["bypass"]:
            path_str = str(file)
            if "w" in mode or "a" in mode or "x" in mode:
                _record_fs(ctx, "fs_write", path_str)
            elif "r" in mode or mode == "":
                _record_fs(ctx, "fs_read", path_str)
        return _original_open(file, mode, *args, **kwargs)

    def patched_remove(path: Any, *args: Any, **kwargs: Any) -> Any:
        result = _original_remove(path, *args, **kwargs)
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_delete", str(path))
        return result

    def patched_unlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        result = _original_unlink(path, *args, **kwargs)
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_delete", str(path))
        return result

    def patched_rename(src: Any, dst: Any, *args: Any, **kwargs: Any) -> Any:
        result = _original_rename(src, dst, *args, **kwargs)
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_delete", str(src))
            _record_fs(ctx, "fs_write", str(dst))
        return result

    def patched_makedirs(name: Any, *args: Any, **kwargs: Any) -> Any:
        result = _original_makedirs(name, *args, **kwargs)
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_write", str(name))
        return result

    def patched_mkdir(path: Any, *args: Any, **kwargs: Any) -> Any:
        result = _original_mkdir(path, *args, **kwargs)
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_write", str(path))
        return result

    def patched_rmtree(path: Any, *args: Any, **kwargs: Any) -> Any:
        if not ctx["state"]["bypass"]:
            _record_fs(ctx, "fs_delete", str(path))
        return _original_rmtree(path, *args, **kwargs)

    builtins.open = patched_open  # type: ignore[assignment]
    os.remove = patched_remove
    os.unlink = patched_unlink
    os.rename = patched_rename  # type: ignore[assignment]
    os.makedirs = patched_makedirs  # type: ignore[assignment]
    os.mkdir = patched_mkdir  # type: ignore[assignment]
    shutil.rmtree = patched_rmtree  # type: ignore[assignment]


def unpatch_filesystem() -> None:
    builtins.open = _original_open  # type: ignore[assignment]
    os.remove = _original_remove
    os.unlink = _original_unlink
    os.rename = _original_rename  # type: ignore[assignment]
    os.makedirs = _original_makedirs  # type: ignore[assignment]
    os.mkdir = _original_mkdir  # type: ignore[assignment]
    shutil.rmtree = _original_rmtree  # type: ignore[assignment]
