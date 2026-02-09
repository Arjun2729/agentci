import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { evaluatePolicy } from '../src/core/policy/evaluate';
import { defaultConfig, loadConfig, saveConfig } from '../src/core/policy/config';
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
    net_protocols: ['https'],
    net_etld_plus_1: ['evil.com'],
    net_hosts: ['evil.com'],
    net_ports: [443],
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
  redaction: { redact_paths: [], redact_urls: [], hash_values: false },
  policy: {
    filesystem: { allow_writes: ['workspace/**'], block_writes: ['/etc/**'], enforce_allowlist: false },
    network: {
      allow_etld_plus_1: ['good.com'],
      allow_hosts: ['api.good.com'],
      enforce_allowlist: true,
      allow_protocols: [],
      block_protocols: [],
      allow_ports: [],
      block_ports: [],
    },
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
      (f) => f.severity === 'BLOCK' && f.category === 'sensitive' && f.message.includes('AWS_SECRET_ACCESS_KEY'),
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
        net_protocols: ['https'],
        net_etld_plus_1: ['good.com'],
        net_hosts: ['api.good.com'],
        net_ports: [443],
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

describe('config', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-config-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('defaultConfig returns valid config with workspace root', () => {
    const cfg = defaultConfig('/my/workspace');
    expect(cfg.version).toBe(1);
    expect(cfg.workspace_root).toBe('/my/workspace');
    expect(cfg.policy.exec.block_commands).toContain('rm');
  });

  it('loadConfig returns default when no path given', () => {
    const cfg = loadConfig(undefined, '/fallback');
    expect(cfg.workspace_root).toBe('/fallback');
  });

  it('loadConfig returns default when file does not exist', () => {
    const cfg = loadConfig(path.join(tmpDir, 'nonexistent.yml'), '/fallback');
    expect(cfg.workspace_root).toBe('/fallback');
  });

  it('loadConfig parses valid YAML config', () => {
    const configPath = path.join(tmpDir, 'agentci.yml');
    fs.writeFileSync(
      configPath,
      `version: 1
policy:
  exec:
    block_commands:
      - dangerous
`,
    );
    const cfg = loadConfig(configPath, tmpDir);
    expect(cfg.policy.exec.block_commands).toContain('dangerous');
  });

  it('loadConfig falls back to default for invalid config', () => {
    const configPath = path.join(tmpDir, 'bad.yml');
    fs.writeFileSync(configPath, 'version: "not-a-number"\n');
    const cfg = loadConfig(configPath, tmpDir);
    expect(cfg.version).toBe(1);
  });

  it('saveConfig writes YAML file', () => {
    const configPath = path.join(tmpDir, 'out', 'config.yml');
    const cfg = defaultConfig(tmpDir);
    saveConfig(configPath, cfg);
    expect(fs.existsSync(configPath)).toBe(true);
    const raw = fs.readFileSync(configPath, 'utf8');
    expect(raw).toContain('version: 1');
  });

  it('loadConfig resolves relative workspace_root', () => {
    const configPath = path.join(tmpDir, 'agentci.yml');
    fs.writeFileSync(configPath, 'version: 1\nworkspace_root: ./sub\n');
    const cfg = loadConfig(configPath, tmpDir);
    expect(cfg.workspace_root).toBe(path.resolve(tmpDir, './sub'));
  });

  it('loadConfig handles redact_hosts legacy field', () => {
    const configPath = path.join(tmpDir, 'agentci.yml');
    fs.writeFileSync(
      configPath,
      `version: 1
redaction:
  redact_hosts:
    - "*.internal.com"
`,
    );
    const cfg = loadConfig(configPath, tmpDir);
    expect(cfg.redaction.redact_urls).toContain('*.internal.com');
  });
});
