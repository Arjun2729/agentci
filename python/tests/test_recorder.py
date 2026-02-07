"""Tests for the Python recorder."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from agentci_recorder.canonicalize import to_etld_plus1, resolve_path_best_effort, normalize_command
from agentci_recorder.writer import TraceWriter
from agentci_recorder.types import make_event


def test_etld_plus1():
    assert to_etld_plus1("api.weather.com") == "weather.com"
    assert to_etld_plus1("localhost") == "localhost"


def test_resolve_path():
    with tempfile.TemporaryDirectory() as root:
        inside = os.path.join(root, "file.txt")
        result = resolve_path_best_effort(inside, root)
        assert result.is_workspace_local is True
        assert result.is_symlink_escape is False


def test_normalize_command():
    cmd, argv = normalize_command("/usr/bin/git", ["status"])
    assert cmd == "git"
    assert argv == ["git", "status"]


def test_writer_buffered_flush():
    with tempfile.TemporaryDirectory() as d:
        trace_path = os.path.join(d, "trace.jsonl")
        writer = TraceWriter(trace_path, buffer_size=2, flush_interval=10.0)

        event1 = make_event("run1", "lifecycle", {"stage": "start"})
        event2 = make_event("run1", "lifecycle", {"stage": "stop"})

        writer.write(event1)
        # Buffer not full yet, file should be empty or have nothing flushed
        writer.write(event2)
        # Buffer full, should have flushed

        writer.close()

        with open(trace_path, "r") as f:
            lines = [l for l in f.readlines() if l.strip()]

        assert len(lines) == 2
        parsed = json.loads(lines[0])
        assert parsed["type"] == "lifecycle"


def test_recorder_start_stop():
    with tempfile.TemporaryDirectory() as d:
        run_dir = os.path.join(d, "run1")
        os.makedirs(run_dir)

        from agentci_recorder.recorder import start_recording, stop_recording

        ctx = start_recording(run_dir=run_dir, run_id="test-run", workspace_root=d)
        assert ctx["run_id"] == "test-run"

        stop_recording(ctx)

        trace_path = os.path.join(run_dir, "trace.jsonl")
        assert os.path.isfile(trace_path)

        with open(trace_path, "r") as f:
            lines = [l for l in f.readlines() if l.strip()]

        assert len(lines) >= 2
        events = [json.loads(l) for l in lines]
        stages = [e["data"]["stage"] for e in events if e["type"] == "lifecycle"]
        assert "start" in stages
        assert "stop" in stages
