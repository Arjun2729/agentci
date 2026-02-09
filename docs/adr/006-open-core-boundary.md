# ADR-006: Open Core Boundary

Date: 2025-02-08
Status: Accepted

## Context

AgentCI needs a sustainable funding model. The project requires ongoing development, security maintenance, and community support.

## Decision

Adopt an **open core** model:

| Tier | License | Includes |
|------|---------|----------|
| Free | MIT | CLI, local dashboard, policy engine, all recorders, integrity verification, HTML reports, baseline management, policy packs |
| Pro | Commercial (license key) | Dashboard authentication, SaaS control plane, ANNPack similarity search, anomaly detection, team features |
| Enterprise | Commercial | Self-hosted control plane, SAML/LDAP SSO, audit logging, compliance reporting |

The boundary principle: **individual developer workflows are always free. Team and infrastructure features are Pro.**

## Consequences

**Positive:**
- Wide adoption through generous free tier
- Revenue from teams and enterprises who need collaboration features
- Clear upgrade path — free users see exactly what Pro adds
- MIT license ensures community trust and contribution

**Negative:**
- Must maintain clear feature boundaries (complexity)
- Risk of community forks if free tier is perceived as too limited
- License key system adds code complexity

## Alternatives Considered

1. **Fully open source (no monetization)** — Sustainable only with grants or support contracts. Rejected because advanced features (SaaS, ANNPack) require dedicated engineering.

2. **Usage-based SaaS** — Free CLI pushes to a hosted API. Rejected because it violates ADR-005 (local-first) and creates vendor lock-in.

3. **Dual license (GPL + commercial)** — Copyleft free tier, commercial for proprietary use. Rejected because GPL creates adoption friction in enterprise environments.
