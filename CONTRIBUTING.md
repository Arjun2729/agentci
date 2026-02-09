# Contributing to AgentCI

Thank you for your interest in contributing to AgentCI.

## Development Setup

```bash
git clone https://github.com/anthropics/agentci.git
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

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new features or bug fixes
- Update documentation if behavior changes
- CI must pass before merge

## Reporting Issues

Open an issue at https://github.com/anthropics/agentci/issues with:
- Steps to reproduce
- Expected vs actual behavior
- Node.js / Python version
- OS and platform

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
