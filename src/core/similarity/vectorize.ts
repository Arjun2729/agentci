import * as fs from 'fs';
import * as path from 'path';
import type { EffectSignature } from '../types.js';

export interface Vocabulary {
  tokens: string[];
  tokenToIndex: Map<string, number>;
  size: number;
}

export function buildVocabulary(signatures: EffectSignature[]): Vocabulary {
  const tokenSet = new Set<string>();

  for (const sig of signatures) {
    for (const w of sig.effects.fs_writes) tokenSet.add(`fs_w:${w}`);
    for (const r of sig.effects.fs_reads_external) tokenSet.add(`fs_r:${r}`);
    for (const d of sig.effects.fs_deletes) tokenSet.add(`fs_d:${d}`);
    for (const p of sig.effects.net_protocols) tokenSet.add(`net_p:${p}`);
    for (const h of sig.effects.net_hosts) tokenSet.add(`net_h:${h}`);
    for (const e of sig.effects.net_etld_plus_1) tokenSet.add(`net_e:${e}`);
    for (const port of sig.effects.net_ports) tokenSet.add(`net_port:${port}`);
    for (const c of sig.effects.exec_commands) tokenSet.add(`exec_c:${c}`);
    for (const a of sig.effects.exec_argv) tokenSet.add(`exec_a:${a}`);
    for (const s of sig.effects.sensitive_keys_accessed) tokenSet.add(`sens:${s}`);
  }

  const tokens = Array.from(tokenSet).sort();
  const tokenToIndex = new Map<string, number>();
  tokens.forEach((token, i) => tokenToIndex.set(token, i));

  return { tokens, tokenToIndex, size: tokens.length };
}

export function buildVocabularyFromRunsDir(runsDir: string): {
  vocab: Vocabulary;
  signatures: Array<{ runId: string; signature: EffectSignature }>;
} {
  const signatures: Array<{ runId: string; signature: EffectSignature }> = [];

  if (!fs.existsSync(runsDir)) return { vocab: { tokens: [], tokenToIndex: new Map(), size: 0 }, signatures };

  const entries = fs.readdirSync(runsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const sigPath = path.join(runsDir, entry.name, 'signature.json');
    if (!fs.existsSync(sigPath)) continue;
    try {
      const sig = JSON.parse(fs.readFileSync(sigPath, 'utf8')) as EffectSignature;
      if (sig.effects) {
        signatures.push({ runId: entry.name, signature: sig });
      }
    } catch {
      // skip invalid
    }
  }

  const vocab = buildVocabulary(signatures.map((s) => s.signature));
  return { vocab, signatures };
}

export function vectorizeSignature(sig: EffectSignature, vocab: Vocabulary): Float64Array {
  const vec = new Float64Array(vocab.size);

  const addTokens = (prefix: string, values: (string | number)[]) => {
    for (const v of values) {
      const idx = vocab.tokenToIndex.get(`${prefix}:${v}`);
      if (idx !== undefined) vec[idx] = 1.0;
    }
  };

  addTokens('fs_w', sig.effects.fs_writes);
  addTokens('fs_r', sig.effects.fs_reads_external);
  addTokens('fs_d', sig.effects.fs_deletes);
  addTokens('net_p', sig.effects.net_protocols);
  addTokens('net_h', sig.effects.net_hosts);
  addTokens('net_e', sig.effects.net_etld_plus_1);
  addTokens('net_port', sig.effects.net_ports);
  addTokens('exec_c', sig.effects.exec_commands);
  addTokens('exec_a', sig.effects.exec_argv);
  addTokens('sens', sig.effects.sensitive_keys_accessed);

  // L2 normalize
  let norm = 0;
  for (let i = 0; i < vec.length; i++) norm += vec[i] * vec[i];
  norm = Math.sqrt(norm);
  if (norm > 0) {
    for (let i = 0; i < vec.length; i++) vec[i] /= norm;
  }

  return vec;
}

export function cosineSimilarity(a: Float64Array, b: Float64Array): number {
  if (a.length !== b.length) return 0;
  if (a.length === 0) return 1;

  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i];

  // Both vectors are already L2-normalized, so dot product = cosine similarity
  return Math.max(0, Math.min(1, dot));
}
