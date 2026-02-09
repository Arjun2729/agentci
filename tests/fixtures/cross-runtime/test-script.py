"""Cross-runtime test script for Python.
Performs: write file, read file, spawn subprocess, access env var.
"""
import os
import subprocess
import tempfile

out_dir = os.environ.get("AGENTCI_TEST_OUT", os.path.join(os.path.dirname(__file__), "out"))
os.makedirs(out_dir, exist_ok=True)

# 1. Write a file
with open(os.path.join(out_dir, "hello.txt"), "w") as f:
    f.write("hello from python")

# 2. Read a file
with open(os.path.join(out_dir, "hello.txt"), "r") as f:
    _ = f.read()

# 3. Spawn subprocess
subprocess.run(["echo", "cross-runtime-test"], capture_output=True)

# 4. Access env var
_ = os.environ.get("HOME")
