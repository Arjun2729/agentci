# Contributing to AgentCI

Thank you for your interest in contributing to AgentCI.

## Development Setup

```bash
git clone https://github.com/Arjun2729/agentci.git
cd agentci
npm install
npm run build
```

### Python recorder

```bash
cd python
pip install -e ".[dev]"
```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Run the full check suite before submitting:

```bash
npm run check    # lint + format + typecheck + test
```

### Individual commands

| Command | Description |
|---------|-------------|
| `npm run build` | Build with tsup |
| `npm test` | Run tests |
| `npm run test:coverage` | Run tests with coverage |
| `npm run lint` | Run ESLint |
| `npm run lint:fix` | Auto-fix ESLint issues |
| `npm run format` | Format with Prettier |
| `npm run format:check` | Check formatting |
| `npm run typecheck` | TypeScript type check |

## Code Standards

- TypeScript strict mode is enabled
- All new code must pass ESLint and Prettier checks
- Write tests for new functionality
- Keep production dependencies minimal
- Never record secret values, file contents, or request/response bodies

## Architecture

```
src/
├── cli/         CLI entry points (Commander.js)
├── core/        Policy evaluation, tracing, signing, schema
├── recorder/    Runtime patching and trace writing
├── dashboard/   Web UI server
├── report/      HTML report generation
├── adapters/    Integration points (e.g., OpenClaw)
```

### Key principles

- **Metadata only**: Record paths, hosts, commands — never contents or values
- **Minimal overhead**: Buffered writes, no synchronous I/O in the hot path
- **Fail open**: Recorder errors must never crash the monitored application
- **Policy as code**: All rules expressed in `.agentci/config.yaml`

## Scope Boundaries

AgentCI is a **metadata-only side-effect recorder and policy engine**. Understanding what it is NOT helps focus contributions:

| AgentCI IS | AgentCI is NOT |
|------------|----------------|
| A flight recorder for observable actions | An LLM debugger or prompt logger |
| A policy engine for side-effect drift | A kernel-level security sandbox |
| A local-first CLI tool | A log aggregator or APM |
| A CI gate for agent-generated PRs | A database or data warehouse |
| A diffing tool for Effect Signatures | A real-time alerting system |

See [docs/adr/](docs/adr/) for the full set of architectural decisions.

## Anti-Patterns

Avoid these when contributing:

1. **Recording too much** — AgentCI captures metadata (paths, hosts, commands), never contents (file bodies, HTTP payloads, secret values). If your change records content, it violates ADR-001.

2. **Failing closed** — Recorder errors must never crash the monitored application. All patch wrappers must catch exceptions and continue silently (ADR-004). If your change adds a patch that can throw into user code, it will be rejected.

3. **Blocking the event loop** — Trace writes are buffered and async. Do not introduce synchronous I/O in the recording hot path. The recorder must add negligible overhead.

4. **OS-specific features** — AgentCI works on any platform where Node.js or Python runs. Do not introduce features that depend on Linux-only syscalls, macOS-only APIs, or Windows-only facilities. Platform detection for graceful degradation is acceptable.

5. **Adding external service dependencies** — All core functionality must work offline with no network access (ADR-005). Cloud integrations belong in the Pro tier (`src/pro/`).

6. **Over-capturing in policy** — Policy should evaluate Effect Signatures, not raw traces. Policy rules operate on sets of paths/hosts/commands, not individual events.

## Rejected Features

These have been explicitly considered and rejected. PRs implementing them will not be accepted without a new ADR reversing the decision.

| Feature | Why Rejected | ADR |
|---------|-------------|-----|
| LLM prompt/completion logging | Privacy risk, scope creep — use LangSmith or Helicone | ADR-003 |
| Token counting / cost tracking | Billing concern, not a side-effect audit concern | ADR-003 |
| Kernel-level sandboxing (seccomp, AppArmor) | Massive complexity, platform-specific, different tool category | ADR-002 |
| Auto-rollback on policy violation | Dangerous — rolling back partial file writes can corrupt state | ADR-002 |
| Real-time push alerts | Requires external service dependency, violates local-first | ADR-005 |
| SQLite/PostgreSQL storage | Adds native deps, complicates git workflows | ADR-007 |
| Auto-generated policies from traces | Policies must be explicit and human-reviewed — auto-generation creates false sense of security | — |
| Windows kernel driver | Extreme platform lock-in, massive maintenance burden | ADR-002 |

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new features or bug fixes
- Update documentation if behavior changes
- CI must pass before merge

## Reporting Issues

Open an issue at https://github.com/Arjun2729/agentci/issues with:
- Steps to reproduce
- Expected vs actual behavior
- Node.js / Python version
- OS and platform

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
