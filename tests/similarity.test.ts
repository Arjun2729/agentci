import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { EffectSignature } from '../src/core/types.js';
import { buildVocabulary, vectorizeSignature, cosineSimilarity } from '../src/core/similarity/vectorize.js';
import { findSimilarRuns } from '../src/core/similarity/search.js';
import { detectAnomaly } from '../src/core/similarity/anomaly.js';

function makeSig(effects: Partial<EffectSignature['effects']>): EffectSignature {
  return {
    meta: {
      signature_version: '1.0',
      normalization_rules_version: '1.0',
      agentci_version: '0.1.0',
      platform: 'linux-x64',
      adapter: 'node-hook',
      scenario_id: 'default',
      node_version: 'v20.0.0',
    },
    effects: {
      fs_writes: [],
      fs_reads_external: [],
      fs_deletes: [],
      net_protocols: [],
      net_etld_plus_1: [],
      net_hosts: [],
      net_ports: [],
      exec_commands: [],
      exec_argv: [],
      sensitive_keys_accessed: [],
      ...effects,
    },
  };
}

function writeRunSignature(runsDir: string, runId: string, sig: EffectSignature): void {
  const runDir = path.join(runsDir, runId);
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(path.join(runDir, 'signature.json'), JSON.stringify(sig, null, 2));
}

describe('similarity - vectorize', () => {
  it('identical signatures have similarity 1.0', () => {
    const sig = makeSig({
      fs_writes: ['src/index.ts', 'src/utils.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['npm'],
    });

    const vocab = buildVocabulary([sig]);
    const vec = vectorizeSignature(sig, vocab);
    expect(cosineSimilarity(vec, vec)).toBeCloseTo(1.0, 5);
  });

  it('completely different signatures have similarity ~0.0', () => {
    const sig1 = makeSig({
      fs_writes: ['a.ts', 'b.ts'],
      net_hosts: ['host-a.com'],
    });
    const sig2 = makeSig({
      exec_commands: ['node', 'npm'],
      sensitive_keys_accessed: ['SECRET_KEY'],
    });

    const vocab = buildVocabulary([sig1, sig2]);
    const vec1 = vectorizeSignature(sig1, vocab);
    const vec2 = vectorizeSignature(sig2, vocab);
    expect(cosineSimilarity(vec1, vec2)).toBeCloseTo(0.0, 5);
  });

  it('partially overlapping signatures have intermediate score', () => {
    const sig1 = makeSig({
      fs_writes: ['src/index.ts', 'src/utils.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['npm'],
    });
    const sig2 = makeSig({
      fs_writes: ['src/index.ts', 'src/other.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['node'],
    });

    const vocab = buildVocabulary([sig1, sig2]);
    const vec1 = vectorizeSignature(sig1, vocab);
    const vec2 = vectorizeSignature(sig2, vocab);
    const sim = cosineSimilarity(vec1, vec2);
    expect(sim).toBeGreaterThan(0.1);
    expect(sim).toBeLessThan(0.95);
  });

  it('vocabulary builds correctly from signatures', () => {
    const sig1 = makeSig({ fs_writes: ['a.ts'], net_hosts: ['h1.com'] });
    const sig2 = makeSig({ fs_writes: ['b.ts'], net_hosts: ['h2.com'] });

    const vocab = buildVocabulary([sig1, sig2]);
    expect(vocab.size).toBe(4); // fs_w:a.ts, fs_w:b.ts, net_h:h1.com, net_h:h2.com
    expect(vocab.tokens).toContain('fs_w:a.ts');
    expect(vocab.tokens).toContain('net_h:h2.com');
  });

  it('vectorization is deterministic', () => {
    const sig = makeSig({
      fs_writes: ['x.ts'],
      net_hosts: ['api.com'],
      exec_commands: ['git'],
    });

    const vocab = buildVocabulary([sig]);
    const vec1 = vectorizeSignature(sig, vocab);
    const vec2 = vectorizeSignature(sig, vocab);
    expect(Array.from(vec1)).toEqual(Array.from(vec2));
  });

  it('empty signatures have zero vectors', () => {
    const sig = makeSig({});
    const vocab = buildVocabulary([sig]);
    expect(vocab.size).toBe(0);
  });
});

describe('similarity - search', () => {
  let tmpDir: string;
  let runsDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-sim-'));
    runsDir = path.join(tmpDir, 'runs');
    fs.mkdirSync(runsDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('finds similar runs from runs directory', () => {
    const baseline = makeSig({
      fs_writes: ['src/index.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['npm'],
    });

    // Write some runs
    writeRunSignature(runsDir, 'run-similar', makeSig({
      fs_writes: ['src/index.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['npm', 'node'],
    }));
    writeRunSignature(runsDir, 'run-different', makeSig({
      fs_writes: ['other.py'],
      exec_commands: ['python'],
    }));

    const results = findSimilarRuns(baseline, runsDir, 10);
    expect(results.length).toBe(2);
    expect(results[0].run_id).toBe('run-similar');
    expect(results[0].score).toBeGreaterThan(results[1].score);
  });

  it('returns empty for empty runs directory', () => {
    const sig = makeSig({ fs_writes: ['test.ts'] });
    const results = findSimilarRuns(sig, runsDir, 10);
    expect(results).toEqual([]);
  });
});

describe('similarity - anomaly detection', () => {
  let tmpDir: string;
  let runsDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-anomaly-'));
    runsDir = path.join(tmpDir, 'runs');
    fs.mkdirSync(runsDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('flags outlier runs as anomalous', () => {
    // Create a cluster of similar runs
    for (let i = 0; i < 5; i++) {
      writeRunSignature(runsDir, `normal-${i}`, makeSig({
        fs_writes: ['src/index.ts', 'src/utils.ts'],
        net_hosts: ['api.openai.com'],
        exec_commands: ['npm'],
      }));
    }

    // Query with a very different signature
    const outlier = makeSig({
      fs_writes: ['completely/different/path.py'],
      net_hosts: ['evil-server.com'],
      exec_commands: ['curl', 'wget'],
      sensitive_keys_accessed: ['AWS_SECRET_ACCESS_KEY'],
    });

    const result = detectAnomaly(outlier, runsDir, { threshold: 0.5 });
    expect(result.is_anomaly).toBe(true);
    expect(result.score).toBeLessThan(0.5);
  });

  it('passes for normal runs', () => {
    // Create similar runs
    for (let i = 0; i < 5; i++) {
      writeRunSignature(runsDir, `normal-${i}`, makeSig({
        fs_writes: ['src/index.ts'],
        net_hosts: ['api.openai.com'],
        exec_commands: ['npm'],
      }));
    }

    // Query with a very similar signature
    const normal = makeSig({
      fs_writes: ['src/index.ts'],
      net_hosts: ['api.openai.com'],
      exec_commands: ['npm'],
    });

    const result = detectAnomaly(normal, runsDir, { threshold: 0.5 });
    expect(result.is_anomaly).toBe(false);
    expect(result.score).toBeGreaterThan(0.5);
  });

  it('returns not anomalous for empty runs dir', () => {
    const sig = makeSig({ fs_writes: ['test.ts'] });
    const result = detectAnomaly(sig, runsDir);
    expect(result.is_anomaly).toBe(false);
    expect(result.score).toBe(1.0);
  });
});
