# ADR-002: No Sandbox — Detection Only

Date: 2025-02-08
Status: Accepted

## Context

Many users ask: "Can AgentCI prevent my agent from doing something bad?" The answer is deliberately no. AgentCI is an observability and policy enforcement tool, not a security sandbox.

## Decision

AgentCI **detects and reports** policy violations but does **not prevent** actions at the kernel level. The `--enforce` flag exits the process on violation, but this is a cooperative mechanism — the agent runs in the same process and could theoretically bypass it.

## Consequences

**Positive:**
- Works on any OS without kernel modules, containers, or root access
- Zero risk of breaking legitimate agent behavior through false-positive blocks
- Simple mental model: record everything, evaluate after
- Portable across Node.js and Python without OS-specific code

**Negative:**
- A malicious or compromised agent can bypass the recorder
- Native addons calling libc directly are not intercepted
- Cannot provide security guarantees against adversarial agents

## Alternatives Considered

1. **Kernel-level sandbox (seccomp, AppArmor, eBPF)** — Would provide true isolation but limits portability to Linux, requires root, and adds significant complexity. Recommended as a complementary tool (Docker, Firecracker) rather than built-in.

2. **Process isolation (separate process with IPC)** — Run the agent in a sandboxed child process. Rejected because it changes the execution model and breaks many agent frameworks.

3. **WASM sandbox** — Run agents in a WebAssembly sandbox. Promising but too immature for general-purpose agent isolation and incompatible with native Node.js modules.
