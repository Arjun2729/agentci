import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/core/policy/evaluate';
import { EffectSignature, PolicyConfig } from '../src/core/types';

const baseSignature: EffectSignature = {
  meta: {
    signature_version: '1.0',
    agentci_version: '0.1.0',
    platform: 'darwin-arm64',
    adapter: 'node-hook',
    scenario_id: 'default',
    node_version: 'v18.17.0'
  },
  effects: {
    fs_writes: ['workspace/output.txt'],
    fs_reads_external: ['/etc/hosts'],
    fs_deletes: [],
    net_etld_plus_1: ['evil.com'],
    net_hosts: ['evil.com'],
    exec_commands: ['rm'],
    exec_argv: ['["rm","-rf","/"]'],
    sensitive_keys_accessed: ['AWS_SECRET_ACCESS_KEY']
  }
};

const config: PolicyConfig = {
  version: 1,
  workspace_root: '/workspace',
  policy: {
    filesystem: { allow_writes: ['workspace/**'], block_writes: ['/etc/**'] },
    network: { allow_etld_plus_1: ['good.com'], allow_hosts: ['api.good.com'] },
    exec: { allow_commands: ['node'], block_commands: ['rm'] },
    sensitive: { block_env: ['AWS_SECRET_ACCESS_KEY'], block_file_globs: [] }
  },
  reporting: { explain_templates: true }
};

describe('policy evaluation', () => {
  it('flags blocked items', () => {
    const findings = evaluatePolicy(baseSignature, config);
    expect(findings.some((f) => f.severity === 'BLOCK')).toBe(true);
  });
});
