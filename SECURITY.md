# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in AgentCI, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@agentci.dev** with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Any relevant logs, screenshots, or proof-of-concept code
4. Your assessment of severity and impact

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with our assessment and remediation timeline
- **Credit** in the release notes (unless you prefer to remain anonymous)

### Scope

The following are in scope for security reports:

- Path traversal or directory escape in the dashboard or report server
- Injection vulnerabilities (XSS, command injection, etc.)
- HMAC/integrity bypass or weakness
- Secret key exposure or leakage
- Authentication/authorization issues in the dashboard
- Denial of service via resource exhaustion

The following are **out of scope**:

- Agent bypass of the recorder (this is a known limitation documented in the README)
- Issues requiring physical access to the host machine
- Social engineering attacks

## Security Design

For details on AgentCI's threat model, trust assumptions, and security best practices, see the [Security Model](README.md#security-model) section in the README.
