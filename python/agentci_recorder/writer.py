"""Buffered trace writer for Python recorder."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import TextIO

from agentci_recorder.types import TraceEvent
from agentci_recorder.logger import logger


class TraceWriter:
    """Buffered, thread-safe trace writer.

    Flushes to disk every `flush_interval` seconds or when the buffer
    reaches `buffer_size` events, whichever comes first.
    """

    def __init__(
        self,
        trace_path: str,
        *,
        buffer_size: int = 64,
        flush_interval: float = 0.25,
    ) -> None:
        self.trace_path = trace_path
        self._buffer: list[str] = []
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval
        self._lock = threading.RLock()
        self._closed = False
        self._file: TextIO | None = None

        os.makedirs(os.path.dirname(trace_path), exist_ok=True)
        self._file = open(trace_path, "a", encoding="utf-8")

        self._timer: threading.Timer | None = None
        self._schedule_flush()

    def _schedule_flush(self) -> None:
        if self._closed:
            return
        self._timer = threading.Timer(self._flush_interval, self._timed_flush)
        self._timer.daemon = True
        self._timer.start()

    def _timed_flush(self) -> None:
        self._do_flush()
        self._schedule_flush()

    def write(self, event: TraceEvent) -> None:
        if self._closed:
            return
        try:
            line = json.dumps(event.to_dict()) + "\n"
        except Exception as e:
            logger.debug(f"Failed to serialize event: {e}")
            return

        with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self._buffer_size:
                self._do_flush()

    def _do_flush(self) -> None:
        with self._lock:
            if not self._buffer or not self._file:
                return
            data = "".join(self._buffer)
            self._buffer.clear()
        try:
            self._file.write(data)
            self._file.flush()
        except Exception as e:
            logger.debug(f"Failed to flush trace: {e}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._timer:
            self._timer.cancel()
        self._do_flush()
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
