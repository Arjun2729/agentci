"""Bootstrap script injected via PYTHONSTARTUP to auto-start recording."""

import os

if os.environ.get("AGENTCI_RUN_DIR"):
    try:
        from agentci_recorder.recorder import start_recording
        start_recording()
    except Exception:
        pass
