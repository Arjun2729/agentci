# ADR-001: Metadata-Only Recording

Date: 2025-02-08
Status: Accepted

## Context

AgentCI records side-effects from AI agent executions. The core question is: how much detail should we capture?

Full content capture (file bodies, HTTP payloads, env var values) would provide maximum debuggability but creates privacy, legal, and storage risks. Users run agents against proprietary codebases containing trade secrets, PII, and credentials.

## Decision

Record **metadata only**: file paths, hostnames, HTTP methods, command names, env var names. Never capture file contents, HTTP request/response bodies, or secret values.

## Consequences

**Positive:**
- Privacy by design — no PII or secrets in traces
- Small trace files — metadata is compact (typically < 100KB per run)
- Trust — users can adopt AgentCI without legal review of data handling
- Simplicity — no need for encryption-at-rest, data retention policies, or redaction pipelines

**Negative:**
- Cannot reconstruct exact agent behavior from traces alone
- Cannot diff file contents (only detect that a file was modified)
- Cannot inspect HTTP payloads for debugging API issues

## Alternatives Considered

1. **Full system call tracing (strace/eBPF)** — Captures everything but is invasive, OS-specific, requires root, and generates massive traces. Rejected for portability and privacy.

2. **Optional content capture** — Allow users to opt in to recording file contents or HTTP bodies. Rejected because even optional capture creates a security surface (accidental credential logging) and complicates the trust model.

3. **Content hashing** — Record SHA256 hashes of file contents without the actual content. Considered for future work (detect content changes without exposing contents) but not in v0.1.
