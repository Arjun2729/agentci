import { describe, it, expect } from 'vitest';
import { diffSignatures } from '../src/core/diff/diff';
import { summarizeFindings, formatFinding } from '../src/core/diff/explain';
import { EffectSignature, PolicyFinding } from '../src/core/types';

const base: EffectSignature = {
  meta: {
    signature_version: '1.0',
    normalization_rules_version: '1.0',
    agentci_version: '0.1.0',
    platform: 'darwin-arm64',
    adapter: 'node-hook',
    scenario_id: 'default',
    node_version: 'v18.17.0',
  },
  effects: {
    fs_writes: ['a.txt'],
    fs_reads_external: [],
    fs_deletes: [],
    net_protocols: ['https'],
    net_etld_plus_1: ['example.com'],
    net_hosts: ['api.example.com'],
    net_ports: [443],
    exec_commands: ['node'],
    exec_argv: ['["node","script.js"]'],
    sensitive_keys_accessed: [],
  },
};

describe('diff', () => {
  it('reports new drift', () => {
    const current: EffectSignature = {
      ...base,
      effects: {
        ...base.effects,
        fs_writes: ['a.txt', 'b.txt'],
        net_hosts: ['api.example.com', 'evil.com'],
      },
    };

    const diff = diffSignatures(base, current);
    expect(diff.drift.fs_writes).toContain('b.txt');
    expect(diff.drift.net_hosts).toContain('evil.com');
  });
});

describe('explain', () => {
  it('summarizeFindings detects blocks', () => {
    const findings: PolicyFinding[] = [
      { severity: 'BLOCK', category: 'exec', message: 'blocked rm' },
      { severity: 'WARN', category: 'network', message: 'new host' },
    ];
    const summary = summarizeFindings(findings);
    expect(summary.hasBlock).toBe(true);
    expect(summary.hasWarn).toBe(true);
  });

  it('summarizeFindings returns false for empty findings', () => {
    const summary = summarizeFindings([]);
    expect(summary.hasBlock).toBe(false);
    expect(summary.hasWarn).toBe(false);
  });

  it('formatFinding includes suggestion when present', () => {
    const finding: PolicyFinding = {
      severity: 'WARN',
      category: 'exec',
      message: 'Unknown command',
      suggestion: 'Add to allow list',
    };
    expect(formatFinding(finding)).toContain('Suggestion: Add to allow list');
  });

  it('formatFinding returns message only when no suggestion', () => {
    const finding: PolicyFinding = {
      severity: 'BLOCK',
      category: 'exec',
      message: 'Blocked command',
    };
    expect(formatFinding(finding)).toBe('Blocked command');
  });
});
