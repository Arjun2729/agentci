"""Structured debug logger for AgentCI Python recorder."""

from __future__ import annotations

import logging
import os
import sys

_LOG_LEVEL = os.environ.get("AGENTCI_DEBUG", "").strip()

logger = logging.getLogger("agentci")

if _LOG_LEVEL:
    level = logging.DEBUG if _LOG_LEVEL == "1" else getattr(logging, _LOG_LEVEL.upper(), logging.DEBUG)
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[agentci %(levelname)s] %(message)s"))
    logger.addHandler(handler)
else:
    logger.setLevel(logging.CRITICAL + 1)
    logger.addHandler(logging.NullHandler())
