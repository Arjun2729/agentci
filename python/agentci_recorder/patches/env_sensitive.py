"""Monkey-patch for detecting access to sensitive environment variables."""

from __future__ import annotations

import os
from typing import Any

from agentci_recorder.logger import logger
from agentci_recorder.types import (
    EffectEventData,
    SensitiveEffectData,
    effect_data_to_dict,
    make_event,
)

_original_environ_class: type | None = None
_patched = False


class _SensitiveEnvProxy:
    """A dict-like wrapper around os.environ that records sensitive key access."""

    def __init__(self, original: os._Environ, ctx: dict[str, Any], blocked_keys: set[str]) -> None:  # type: ignore[type-arg]
        object.__setattr__(self, "_original", original)
        object.__setattr__(self, "_ctx", ctx)
        object.__setattr__(self, "_blocked", blocked_keys)

    def _record_access(self, key: str) -> None:
        ctx = object.__getattribute__(self, "_ctx")
        try:
            data = EffectEventData(
                category="sensitive_access",
                kind="observed",
                sensitive=SensitiveEffectData(type="env_var", key_name=key),
            )
            ctx["writer"].write(
                make_event(ctx["run_id"], "effect", effect_data_to_dict(data))
            )
        except Exception as e:
            logger.debug(f"Failed to record sensitive env access: {e}")

    def __getitem__(self, key: str) -> str:
        blocked = object.__getattribute__(self, "_blocked")
        if key in blocked:
            self._record_access(key)
        return object.__getattribute__(self, "_original")[key]

    def get(self, key: str, default: str | None = None) -> str | None:
        blocked = object.__getattribute__(self, "_blocked")
        if key in blocked:
            self._record_access(key)
        return object.__getattribute__(self, "_original").get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in object.__getattribute__(self, "_original")

    def __setitem__(self, key: str, value: str) -> None:
        object.__getattribute__(self, "_original")[key] = value

    def __delitem__(self, key: str) -> None:
        del object.__getattribute__(self, "_original")[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(object.__getattribute__(self, "_original"))

    def __len__(self) -> int:
        return len(object.__getattribute__(self, "_original"))

    def keys(self):  # type: ignore[no-untyped-def]
        return object.__getattribute__(self, "_original").keys()

    def values(self):  # type: ignore[no-untyped-def]
        return object.__getattribute__(self, "_original").values()

    def items(self):  # type: ignore[no-untyped-def]
        return object.__getattribute__(self, "_original").items()

    def __repr__(self) -> str:
        return repr(object.__getattribute__(self, "_original"))


_original_environ: Any = None


def patch_env_sensitive(ctx: dict[str, Any], blocked_keys: list[str]) -> None:
    global _patched, _original_environ
    if _patched or not blocked_keys:
        return
    _original_environ = os.environ
    os.environ = _SensitiveEnvProxy(os.environ, ctx, set(blocked_keys))  # type: ignore[assignment]
    _patched = True


def unpatch_env_sensitive() -> None:
    global _patched, _original_environ
    if not _patched:
        return
    if _original_environ is not None:
        os.environ = _original_environ
    _patched = False
