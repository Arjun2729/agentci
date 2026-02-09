import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../src/core/policy/evaluate';
import { EffectSignature, PolicyConfig } from '../src/core/types';

const baseSignature: EffectSignature = {
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
    fs_writes: ['workspace/output.txt'],
    fs_reads_external: ['/etc/hosts'],
    fs_deletes: [],
    net_etld_plus_1: ['evil.com'],
    net_hosts: ['evil.com'],
    exec_commands: ['rm'],
    exec_argv: ['["rm","-rf","/"]'],
    sensitive_keys_accessed: ['AWS_SECRET_ACCESS_KEY'],
  },
};

const config: PolicyConfig = {
  version: 1,
  workspace_root: '/workspace',
  normalization: {
    version: '1.0',
    filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: [] },
    network: { normalize_hosts: true },
    exec: { argv_mode: 'hash', mask_patterns: [] },
  },
  policy: {
    filesystem: { allow_writes: ['workspace/**'], block_writes: ['/etc/**'], enforce_allowlist: false },
    network: { allow_etld_plus_1: ['good.com'], allow_hosts: ['api.good.com'], enforce_allowlist: true },
    exec: { allow_commands: ['node'], block_commands: ['rm'], enforce_allowlist: true },
    sensitive: { block_env: ['AWS_SECRET_ACCESS_KEY'], block_file_globs: [] },
  },
  reporting: { explain_templates: true },
};

describe('policy evaluation', () => {
  it('blocks exec commands in block_commands list', () => {
    const findings = evaluatePolicy(baseSignature, config);
    const execBlock = findings.find(
      (f) => f.severity === 'BLOCK' && f.category === 'exec' && f.message.includes("'rm'"),
    );
    expect(execBlock).toBeDefined();
    expect(execBlock!.message).toContain('blocked by policy.exec.block_commands');
  });

  it('blocks network hosts not in allow list', () => {
    const findings = evaluatePolicy(baseSignature, config);
    const netBlock = findings.find(
      (f) => f.severity === 'BLOCK' && f.category === 'network' && f.message.includes('evil.com'),
    );
    expect(netBlock).toBeDefined();
    expect(netBlock!.message).toContain('not allowed');
  });

  it('blocks sensitive env var access', () => {
    const findings = evaluatePolicy(baseSignature, config);
    const sensitiveBlock = findings.find(
      (f) =>
        f.severity === 'BLOCK' &&
        f.category === 'sensitive' &&
        f.message.includes('AWS_SECRET_ACCESS_KEY'),
    );
    expect(sensitiveBlock).toBeDefined();
    expect(sensitiveBlock!.message).toContain('env var');
  });

  it('does not flag allowed writes', () => {
    const findings = evaluatePolicy(baseSignature, config);
    const writeFindings = findings.filter(
      (f) => f.category === 'filesystem' && f.message.includes('workspace/output.txt'),
    );
    // workspace/output.txt matches allow_writes: ['workspace/**'], so no findings
    expect(writeFindings.length).toBe(0);
  });

  it('does not flag allowed hosts', () => {
    const allowedSig: EffectSignature = {
      ...baseSignature,
      effects: {
        ...baseSignature.effects,
        net_hosts: ['api.good.com'],
        net_etld_plus_1: ['good.com'],
        exec_commands: ['node'],
        sensitive_keys_accessed: [],
      },
    };
    const findings = evaluatePolicy(allowedSig, config);
    const netFindings = findings.filter((f) => f.category === 'network');
    expect(netFindings.length).toBe(0);
  });

  it('returns empty findings for clean signature', () => {
    const cleanSig: EffectSignature = {
      ...baseSignature,
      effects: {
        fs_writes: ['workspace/src/index.ts'],
        fs_reads_external: [],
        fs_deletes: [],
        net_etld_plus_1: ['good.com'],
        net_hosts: ['api.good.com'],
        exec_commands: ['node'],
        exec_argv: ['["node","index.js"]'],
        sensitive_keys_accessed: [],
      },
    };
    const findings = evaluatePolicy(cleanSig, config);
    const blocks = findings.filter((f) => f.severity === 'BLOCK');
    expect(blocks.length).toBe(0);
  });

  it('returns the correct total number of block findings', () => {
    const findings = evaluatePolicy(baseSignature, config);
    const blocks = findings.filter((f) => f.severity === 'BLOCK');
    // evil.com (network), rm (exec), AWS_SECRET_ACCESS_KEY (sensitive) = 3 blocks
    expect(blocks.length).toBe(3);
  });
});
