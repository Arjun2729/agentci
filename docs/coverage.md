# Recorder Coverage and Bypass Notes

AgentCI is a runtime patcher, not a kernel sandbox. It records best‑effort observability for common APIs and fails fast only when those APIs are used.

## Node.js Recorder Coverage

Recorded:
- Filesystem: `fs.writeFile*`, `fs.appendFile*`, `fs.mkdir*`, `fs.readFile*`, `fs.unlink*`, `fs.rm*`, `fs.rename*`
- Filesystem (promises): `fs.promises.writeFile`, `appendFile`, `mkdir`, `readFile`, `unlink`, `rm`, `rename`
- Subprocess: `child_process.spawn`, `exec`, `execFile`, `fork`, `execSync`, `spawnSync`, `execFileSync`
- Network: `http.request`, `https.request`, global `fetch`, `undici.request`, `undici.fetch` (if available)
- Sensitive env: `process.env` access for configured keys

Not recorded (examples):
- `fs.createReadStream` / `createWriteStream`
- `undici` direct usage and other HTTP client libs not using `http/https` or `fetch`
- Raw sockets, WebSockets, DNS APIs
- Native addons or direct syscalls

## Python Recorder Coverage

Recorded:
- Filesystem: `open()`, `os.remove`, `os.unlink`, `os.rename`, `os.makedirs`, `os.mkdir`, `shutil.rmtree`
- Network: `urllib.request.urlopen`, `http.client.HTTPConnection.request`, `HTTPSConnection.request`, `requests.Session.request` (if installed)
- Subprocess: `subprocess.Popen`, `subprocess.run`
- Sensitive env: `os.environ` access for configured keys
- Sensitive file reads: `.env`/blocked globs when `open()` is used

Not recorded (examples):
- `requests` / `urllib3` / `aiohttp` (unless they call patched stdlib functions)
- Raw sockets
- Native extensions

## Recommended Hardening

- Run in CI with `agentci record --enforce` when you need fail‑fast behavior.
- Lock down your policy (`enforce_allowlist` for network and exec).
- Use baselines + PR diffs to catch new drift even when a call path bypasses recorder hooks.

If you need coverage for a specific library, open an issue and include a minimal repro.
