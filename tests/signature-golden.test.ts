import { describe, it, expect } from 'vitest';
import path from 'path';
import { summarizeTrace } from '../src/core/signature/summarize.js';
import { defaultConfig } from './helpers/arbitraries.js';

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'golden');

function goldenConfig() {
  const config = defaultConfig();
  // Disable home collapse for deterministic tests across machines
  config.normalization.filesystem.collapse_home = false;
  config.normalization.filesystem.collapse_temp = false;
  return config;
}

describe('golden signature tests', () => {
  it('fs-only trace produces correct signature', () => {
    const sig = summarizeTrace(path.join(FIXTURES_DIR, 'fs-only.jsonl'), goldenConfig(), '0.1.0');

    expect(sig.effects.fs_writes).toEqual(['src/index.ts', 'src/utils.ts']);
    expect(sig.effects.fs_reads_external).toEqual(['/etc/passwd']);
    expect(sig.effects.fs_deletes).toEqual(['tmp/cache.json']);
    expect(sig.effects.net_hosts).toEqual([]);
    expect(sig.effects.exec_commands).toEqual([]);
    expect(sig.effects.sensitive_keys_accessed).toEqual([]);
    expect(sig.meta.adapter).toBe('node-hook');
  });

  it('network-only trace produces correct signature', () => {
    const sig = summarizeTrace(path.join(FIXTURES_DIR, 'network-only.jsonl'), goldenConfig(), '0.1.0');

    expect(sig.effects.fs_writes).toEqual([]);
    expect(sig.effects.net_hosts).toEqual(['api.openai.com', 'example.com', 'registry.npmjs.org']);
    expect(sig.effects.net_etld_plus_1).toEqual(['example.com', 'npmjs.org', 'openai.com']);
    expect(sig.effects.net_protocols).toEqual(['http', 'https']);
    expect(sig.effects.net_ports).toEqual([443, 8080]);
    expect(sig.effects.exec_commands).toEqual([]);
  });

  it('exec-only trace produces correct signature', () => {
    const sig = summarizeTrace(path.join(FIXTURES_DIR, 'exec-only.jsonl'), goldenConfig(), '0.1.0');

    expect(sig.effects.fs_writes).toEqual([]);
    expect(sig.effects.net_hosts).toEqual([]);
    expect(sig.effects.exec_commands).toEqual(['git', 'node', 'npm']);
    expect(sig.effects.exec_argv.length).toBe(3);
  });

  it('mixed trace produces correct signature with all categories', () => {
    const sig = summarizeTrace(path.join(FIXTURES_DIR, 'mixed.jsonl'), goldenConfig(), '0.1.0');

    expect(sig.effects.fs_writes).toEqual(['src/app.ts']);
    expect(sig.effects.fs_reads_external).toEqual([]);
    expect(sig.effects.net_hosts).toEqual(['api.openai.com']);
    expect(sig.effects.net_etld_plus_1).toEqual(['openai.com']);
    expect(sig.effects.exec_commands).toEqual(['npm']);
    expect(sig.effects.sensitive_keys_accessed).toEqual(['OPENAI_API_KEY']);
  });

  it('edge-cases trace handles unicode paths and long hostnames', () => {
    const sig = summarizeTrace(path.join(FIXTURES_DIR, 'edge-cases.jsonl'), goldenConfig(), '0.1.0');

    expect(sig.effects.fs_writes).toContain('src/héllo wörld.ts');
    expect(sig.effects.net_hosts).toContain(
      'this-is-a-really-long-hostname-that-tests-boundary-conditions.example.com',
    );
    // /usr/local/bin/node should normalize to just 'node'
    expect(sig.effects.exec_commands).toEqual(['node']);
  });

  it('all golden fixtures produce deterministic signatures', () => {
    const fixtures = ['fs-only', 'network-only', 'exec-only', 'mixed', 'edge-cases'];
    const config = goldenConfig();

    for (const name of fixtures) {
      const sig1 = summarizeTrace(path.join(FIXTURES_DIR, `${name}.jsonl`), config, '0.1.0');
      const sig2 = summarizeTrace(path.join(FIXTURES_DIR, `${name}.jsonl`), config, '0.1.0');

      // Strip platform-specific meta fields for comparison
      const effects1 = sig1.effects;
      const effects2 = sig2.effects;
      expect(effects1).toEqual(effects2);
    }
  });

  it('snapshot: all golden signatures match', () => {
    const fixtures = ['fs-only', 'network-only', 'exec-only', 'mixed', 'edge-cases'];
    const config = goldenConfig();

    const signatures: Record<string, unknown> = {};
    for (const name of fixtures) {
      const sig = summarizeTrace(path.join(FIXTURES_DIR, `${name}.jsonl`), config, '0.1.0');
      signatures[name] = sig.effects;
    }

    expect(signatures).toMatchSnapshot();
  });
});
