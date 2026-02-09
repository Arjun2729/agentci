# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-08

### Added

- **Node.js Recorder** — runtime monkey-patching via `--require` for fs, network, child_process, fetch, and process.env
- **Python Recorder** — stdlib monkey-patching for file I/O, network, subprocess, and os.environ
- **Effect Signatures** — stable JSON summaries of all recorded side-effects per run
- **Policy Engine** — YAML-based policy configuration with allow/block rules for filesystem, network, exec, and sensitive access
- **Diff Engine** — compare two signatures and produce categorized findings (INFO/WARN/BLOCK)
- **HMAC-SHA256 Trace Integrity** — per-project secret key with timing-safe verification
- **HTML Reports** — self-contained, single-file reports with CSP headers
- **Dashboard** — web UI for browsing runs, viewing signatures, and checking integrity
- **CLI Commands** — `adopt`, `record`, `summarize`, `diff`, `verify`, `report`, `serve`, `dashboard`
- **OpenClaw Adapter** — `emitToolCall()` / `emitToolResult()` for framework integration
- **Rate Limiting** — per-IP dashboard rate limiting and per-second writer rate limiting
- **Symlink Detection** — detects symlink escape attacks in path canonicalization
- **Docker Support** — multi-stage Dockerfile with non-root user, healthcheck, and Trivy scanning
- **CI Pipeline** — GitHub Actions with multi-version Node/Python testing, linting, and security audit
- **Release Pipeline** — npm + PyPI publishing with provenance signatures and clean-tree verification
