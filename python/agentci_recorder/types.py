"""Core types for AgentCI Python recorder."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Optional


EffectCategory = Literal[
    "fs_write", "fs_read", "fs_delete",
    "net_outbound", "exec", "sensitive_access",
]

EffectKind = Literal["declared", "observed", "inferred"]


@dataclass
class FsEffectData:
    path_requested: str
    path_resolved: str
    is_workspace_local: bool


@dataclass
class NetEffectData:
    host_raw: str
    host_etld_plus_1: str
    method: str
    protocol: Literal["http", "https"]
    port: Optional[int] = None


@dataclass
class ExecEffectData:
    command_raw: str
    argv_normalized: list[str]


@dataclass
class SensitiveEffectData:
    type: Literal["env_var", "file_read"]
    key_name: Optional[str] = None


@dataclass
class EffectEventData:
    category: EffectCategory
    kind: EffectKind
    fs: Optional[FsEffectData] = None
    net: Optional[NetEffectData] = None
    exec: Optional[ExecEffectData] = None
    sensitive: Optional[SensitiveEffectData] = None


@dataclass
class TraceEvent:
    id: str
    timestamp: float
    run_id: str
    type: Literal["lifecycle", "tool_call", "tool_result", "effect"]
    data: dict[str, Any]
    metadata: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "type": self.type,
            "data": self.data,
        }
        if self.metadata:
            d["metadata"] = self.metadata
        return d


def make_event(
    run_id: str,
    event_type: str,
    data: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
) -> TraceEvent:
    return TraceEvent(
        id=str(uuid.uuid4()),
        timestamp=time.time() * 1000,
        run_id=run_id,
        type=event_type,  # type: ignore[arg-type]
        data=data,
        metadata=metadata,
    )


def effect_data_to_dict(data: EffectEventData) -> dict[str, Any]:
    d: dict[str, Any] = {"category": data.category, "kind": data.kind}
    if data.fs:
        d["fs"] = asdict(data.fs)
    if data.net:
        d["net"] = asdict(data.net)
    if data.exec:
        d["exec"] = asdict(data.exec)
    if data.sensitive:
        d["sensitive"] = {k: v for k, v in asdict(data.sensitive).items() if v is not None}
    return d
