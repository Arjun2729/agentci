# ADR-004: Fail-Open Design

Date: 2025-02-08
Status: Accepted

## Context

Runtime monkey-patching is inherently fragile. What happens when the recorder encounters an unexpected error — a new API shape, a race condition, or a type mismatch?

## Decision

Recorder errors must **never crash the monitored application**. All patch wrappers catch exceptions and continue silently. If recording fails for a specific event, that event is lost but the application continues normally.

## Consequences

**Positive:**
- Low adoption risk — AgentCI cannot cause production incidents
- Users can enable recording in CI and production without fear
- Gradual rollout is safe — failures degrade to "no recording" not "app crash"

**Negative:**
- Some events may be silently dropped
- Users may not notice if recording is broken (mitigated by lifecycle start/stop events and AGENTCI_DEBUG logging)
- Makes it harder to debug recorder issues (errors are swallowed)

## Alternatives Considered

1. **Fail-closed (crash on error)** — Guarantees complete traces but makes AgentCI risky to adopt. No production team will deploy a tool that can crash their application.

2. **Fail with warning** — Log a warning to stderr on every dropped event. Rejected as too noisy for production use. AGENTCI_DEBUG=1 provides this for debugging.

3. **Bounded failure tolerance** — Crash after N consecutive errors. Considered but adds complexity without clear benefit. If the recorder is fundamentally broken, the lifecycle stop event will be missing, which is detectable.
