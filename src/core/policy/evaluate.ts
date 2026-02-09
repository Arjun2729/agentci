import path from 'path';
import { EffectSignature, PolicyConfig, PolicyFinding } from '../types';
import { expandTilde, matchHost, matchKey, matchPath, normalizePathForMatch } from './match';
import { toEtldPlus1 } from '../../recorder/canonicalize';

function isAbsolute(p: string): boolean {
  return path.isAbsolute(p) || /^[A-Za-z]:\\/.test(p);
}

function isSubpath(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  if (!relative) return true;
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}

export function evaluatePolicy(signature: EffectSignature, config: PolicyConfig): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  const workspaceRoot = path.resolve(config.workspace_root);

  const allowWrites = config.policy.filesystem.allow_writes || [];
  const blockWrites = config.policy.filesystem.block_writes || [];

  for (const writePath of signature.effects.fs_writes) {
    const absolute = isAbsolute(writePath);
    if (absolute) {
      const expanded = expandTilde(writePath);
      if (!isSubpath(expanded, workspaceRoot)) {
        findings.push({
          severity: 'BLOCK',
          category: 'filesystem',
          message: `Filesystem Violation (BLOCK): write resolved outside workspace root: ${writePath}`
        });
        continue;
      }
    }

    const candidate = absolute
      ? normalizePathForMatch(path.relative(workspaceRoot, writePath))
      : normalizePathForMatch(writePath);

    if (matchPath(blockWrites, absolute ? expandTilde(writePath) : candidate)) {
      findings.push({
        severity: 'BLOCK',
        category: 'filesystem',
        message: `Filesystem Violation (BLOCK): write blocked by policy: ${writePath}`
      });
      continue;
    }

    if (!matchPath(allowWrites, candidate)) {
      findings.push({
        severity: config.policy.filesystem.enforce_allowlist ? 'BLOCK' : 'WARN',
        category: 'filesystem',
        message: `Filesystem Violation (${config.policy.filesystem.enforce_allowlist ? 'BLOCK' : 'WARN'}): write not in allow_writes: ${writePath}`
      });
    }
  }

  const allowedEtlds = config.policy.network.allow_etld_plus_1.map((value) => value.toLowerCase());
  const hasNetworkAllowlist =
    config.policy.network.allow_hosts.length > 0 || config.policy.network.allow_etld_plus_1.length > 0;
  for (const host of signature.effects.net_hosts) {
    const hostAllowed = matchHost(config.policy.network.allow_hosts, host);
    const etld = toEtldPlus1(host).toLowerCase();
    const etldAllowed = allowedEtlds.includes(etld);
    if (!hostAllowed && !etldAllowed && (config.policy.network.enforce_allowlist || hasNetworkAllowlist)) {
      findings.push({
        severity: 'BLOCK',
        category: 'network',
        message: `Network Drift (BLOCK): Host '${host}' (eTLD+1: ${etld}) not allowed by policy.network.allow_*`
      });
    }
  }

  const allowProtocols = config.policy.network.allow_protocols.map((value) => value.toLowerCase());
  const blockProtocols = config.policy.network.block_protocols.map((value) => value.toLowerCase());
  for (const protocol of signature.effects.net_protocols || []) {
    const normalized = protocol.toLowerCase();
    if (blockProtocols.includes(normalized)) {
      findings.push({
        severity: 'BLOCK',
        category: 'network',
        message: `Network Violation (BLOCK): protocol '${protocol}' is blocked by policy.network.block_protocols`,
      });
      continue;
    }
    if (allowProtocols.length && !allowProtocols.includes(normalized)) {
      findings.push({
        severity: 'BLOCK',
        category: 'network',
        message: `Network Violation (BLOCK): protocol '${protocol}' not in allow_protocols`,
      });
    }
  }

  const allowPorts = new Set(config.policy.network.allow_ports);
  const blockPorts = new Set(config.policy.network.block_ports);
  for (const port of signature.effects.net_ports || []) {
    if (blockPorts.has(port)) {
      findings.push({
        severity: 'BLOCK',
        category: 'network',
        message: `Network Violation (BLOCK): port '${port}' is blocked by policy.network.block_ports`,
      });
      continue;
    }
    if (allowPorts.size && !allowPorts.has(port)) {
      findings.push({
        severity: 'BLOCK',
        category: 'network',
        message: `Network Violation (BLOCK): port '${port}' not in allow_ports`,
      });
    }
  }

  for (const cmd of signature.effects.exec_commands) {
    if (config.policy.exec.block_commands.includes(cmd)) {
      findings.push({
        severity: 'BLOCK',
        category: 'exec',
        message: `Exec Violation (BLOCK): command '${cmd}' is blocked by policy.exec.block_commands`
      });
      continue;
    }
    if (!config.policy.exec.allow_commands.includes(cmd)) {
      findings.push({
        severity: config.policy.exec.enforce_allowlist ? 'BLOCK' : 'WARN',
        category: 'exec',
        message: `Exec Violation (${config.policy.exec.enforce_allowlist ? 'BLOCK' : 'WARN'}): command '${cmd}' not in allow_commands (not blocked)`
      });
    }
  }

  for (const sensitive of signature.effects.sensitive_keys_accessed) {
    if (matchKey(config.policy.sensitive.block_env, sensitive)) {
      findings.push({
        severity: 'BLOCK',
        category: 'sensitive',
        message: `Sensitive Access (BLOCK): env var '${sensitive}' accessed`
      });
      continue;
    }

    const expanded = expandTilde(sensitive);
    if (matchPath(config.policy.sensitive.block_file_globs, expanded)) {
      findings.push({
        severity: 'BLOCK',
        category: 'sensitive',
        message: `Sensitive Access (BLOCK): file access '${sensitive}' matches blocked globs`
      });
    }
  }

  return findings;
}
