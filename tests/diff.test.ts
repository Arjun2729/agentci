import { describe, it, expect } from 'vitest';
import { diffSignatures } from '../src/core/diff/diff';
import { EffectSignature } from '../src/core/types';

const base: EffectSignature = {
  meta: {
    signature_version: '1.0',
    agentci_version: '0.1.0',
    platform: 'darwin-arm64',
    adapter: 'node-hook',
    scenario_id: 'default',
    node_version: 'v18.17.0'
  },
  effects: {
    fs_writes: ['a.txt'],
    fs_reads_external: [],
    fs_deletes: [],
    net_etld_plus_1: ['example.com'],
    net_hosts: ['api.example.com'],
    exec_commands: ['node'],
    exec_argv: ['["node","script.js"]'],
    sensitive_keys_accessed: []
  }
};

describe('diff', () => {
  it('reports new drift', () => {
    const current: EffectSignature = {
      ...base,
      effects: {
        ...base.effects,
        fs_writes: ['a.txt', 'b.txt'],
        net_hosts: ['api.example.com', 'evil.com']
      }
    };

    const diff = diffSignatures(base, current);
    expect(diff.drift.fs_writes).toContain('b.txt');
    expect(diff.drift.net_hosts).toContain('evil.com');
  });
});
