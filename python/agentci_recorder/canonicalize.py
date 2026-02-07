"""Path and hostname canonicalization for Python recorder."""

from __future__ import annotations

import os
import posixpath
from typing import NamedTuple

from agentci_recorder.logger import logger

try:
    import tldextract
except ImportError:
    tldextract = None  # type: ignore[assignment]


class ResolvedPath(NamedTuple):
    requested_abs: str
    resolved_abs: str
    is_workspace_local: bool
    is_symlink_escape: bool


def to_etld_plus1(host: str) -> str:
    trimmed = host.strip().lower()
    if tldextract is None:
        logger.debug("tldextract not installed, returning raw host")
        return trimmed
    try:
        ext = tldextract.extract(trimmed)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception as e:
        logger.debug(f"tldextract failed for {host}: {e}")
    return trimmed


def _safe_realpath(p: str) -> str | None:
    try:
        return os.path.realpath(p)
    except Exception:
        return None


def _is_subpath(target: str, root: str) -> bool:
    try:
        rel = os.path.relpath(target, root)
        return not rel.startswith("..") and not os.path.isabs(rel)
    except ValueError:
        return False


def resolve_path_best_effort(input_path: str, workspace_root: str) -> ResolvedPath:
    workspace_resolved = _safe_realpath(workspace_root) or os.path.abspath(workspace_root)
    workspace_original = os.path.abspath(workspace_root)
    requested_abs = os.path.abspath(input_path)
    resolved_abs = _safe_realpath(requested_abs) or requested_abs

    requested_inside = _is_subpath(requested_abs, workspace_resolved) or _is_subpath(
        requested_abs, workspace_original
    )
    resolved_inside = _is_subpath(resolved_abs, workspace_resolved) or _is_subpath(
        resolved_abs, workspace_original
    )

    return ResolvedPath(
        requested_abs=requested_abs,
        resolved_abs=resolved_abs,
        is_workspace_local=resolved_inside or requested_inside,
        is_symlink_escape=requested_inside and not resolved_inside,
    )


def to_workspace_path(
    resolved_abs: str, workspace_root: str
) -> tuple[str, bool]:
    """Return (relative_or_abs_path, is_external)."""
    workspace_resolved = _safe_realpath(workspace_root) or os.path.abspath(workspace_root)
    workspace_original = os.path.abspath(workspace_root)

    if _is_subpath(resolved_abs, workspace_resolved):
        return os.path.relpath(resolved_abs, workspace_resolved), False
    if _is_subpath(resolved_abs, workspace_original):
        return os.path.relpath(resolved_abs, workspace_original), False
    return resolved_abs, True


def normalize_command(command: str, args: list[str]) -> tuple[str, list[str]]:
    base = os.path.basename(command)
    normalized_args = [_normalize_arg(a) for a in args]
    cmd = base or command
    return cmd, [cmd, *normalized_args]


def _normalize_arg(arg: str) -> str:
    if not arg:
        return arg
    if "/tmp/" in arg or "\\Temp\\" in arg or "\\tmp\\" in arg:
        return "<temp>"
    return arg
