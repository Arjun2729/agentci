# ADR-005: Local-First Default

Date: 2025-02-08
Status: Accepted

## Context

Developer tools increasingly require cloud accounts, API keys, and internet connectivity. This creates friction for adoption, raises privacy concerns, and creates vendor lock-in.

## Decision

All core AgentCI functionality works **locally, offline, with no external services**. Traces, signatures, baselines, and policies are stored as files in the `.agentci/` directory. The SaaS control plane is an optional Pro feature, never required.

## Consequences

**Positive:**
- Zero setup friction — `npm install agentci && agentci init` works immediately
- Privacy — no data leaves the user's machine unless they opt in
- Git-friendly — `.agentci/` directory can be committed (except `secret`)
- Offline-capable — works in air-gapped environments
- No vendor lock-in — switch tools by switching CLI commands

**Negative:**
- Team collaboration requires manual baseline sharing (git) or Pro SaaS
- No centralized dashboard without Pro
- No automatic alerting or notifications without integration work

## Alternatives Considered

1. **Cloud-first** — Require a cloud account for any usage. Rejected because it limits adoption and raises privacy concerns.

2. **Hybrid default** — Local recording with optional cloud sync by default. Rejected because "optional" cloud features often become effectively required over time.

3. **Peer-to-peer sync** — Sync baselines between developers via P2P. Interesting but overly complex for v0.1. Git provides this naturally.
