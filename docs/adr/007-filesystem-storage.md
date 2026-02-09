# ADR-007: Filesystem Storage, No Database

Date: 2025-02-08
Status: Accepted

## Context

AgentCI stores traces, signatures, baselines, checksums, and configuration. Where should this data live?

## Decision

Store all data as **files in the `.agentci/` directory**. No database dependency (SQLite, PostgreSQL, or otherwise). Directory structure:

```
.agentci/
├── config.yaml          # Policy configuration
├── secret               # HMAC signing key (0o600)
├── baseline.json        # Current baseline signature
├── baseline.meta.json   # Baseline metadata
└── runs/
    └── <run_id>/
        ├── trace.jsonl
        ├── trace.checksum
        ├── signature.json
        └── signature.checksum
```

## Consequences

**Positive:**
- Zero external dependencies — no database to install, configure, or maintain
- Git-friendly — baselines and configs can be committed and reviewed in PRs
- Simple mental model — `ls .agentci/runs/` shows all runs
- Portable — works on any filesystem
- Easy backup — `cp -r .agentci/ backup/`

**Negative:**
- Limited query performance at scale (mitigated by ANNPack indexes for similarity search)
- No concurrent write safety (acceptable for single-machine use)
- No built-in TTL or garbage collection (users manage with `rm -rf .agentci/runs/old-*`)

## Alternatives Considered

1. **SQLite** — Would enable SQL queries over traces. Rejected because it adds a native dependency (binary), complicates git workflows, and most queries are "read latest run" or "diff two signatures" which don't need SQL.

2. **PostgreSQL/MySQL** — Full relational database. Rejected as massive overkill for a developer CLI tool. Appropriate for the SaaS control plane (Pro tier) if needed in the future.

3. **LevelDB/RocksDB** — Embedded key-value store. Rejected because it adds native dependencies and the file-per-run model is simpler for the common case.
