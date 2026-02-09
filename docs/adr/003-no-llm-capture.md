# ADR-003: No LLM Capture

Date: 2025-02-08
Status: Accepted

## Context

AI agents make LLM API calls (to OpenAI, Anthropic, etc.) as part of their operation. Should AgentCI record the prompts, completions, or token usage?

## Decision

AgentCI does **not** capture LLM prompts, completions, reasoning traces, or token counts. It records only that an HTTP request was made to `api.openai.com` (or similar) — the same metadata-only approach used for all network activity.

## Consequences

**Positive:**
- Consistent with ADR-001 (metadata only)
- No risk of logging PII embedded in prompts
- No risk of logging proprietary system prompts or trade secrets
- Traces remain small and fast to process

**Negative:**
- Cannot debug agent reasoning from AgentCI traces
- Cannot track LLM costs or token usage
- Cannot detect prompt injection attacks from traces

## Alternatives Considered

1. **Optional prompt logging** — Allow users to opt in. Rejected because it violates the metadata-only principle and creates a security surface (system prompts, PII in user messages).

2. **Token counting only** — Record token counts without content. Rejected as scope creep — this is a billing/cost concern, not a side-effect audit concern.

3. **Integration with LLM observability tools** — Recommend LangSmith, Helicone, or Braintrust for LLM-specific observability. AgentCI focuses on the complementary problem: what did the agent *do* with those LLM responses?
