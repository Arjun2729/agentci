import type { EffectSignature } from '../types.js';
import { buildVocabularyFromRunsDir, vectorizeSignature, cosineSimilarity } from './vectorize.js';

export interface SimilarRun {
  run_id: string;
  score: number;
  signature: EffectSignature;
}

/**
 * Find runs most similar to a query signature using brute-force cosine similarity.
 * This is the free-tier implementation — no external dependencies required.
 */
export function findSimilarRuns(
  querySignature: EffectSignature,
  runsDir: string,
  limit: number = 10,
): SimilarRun[] {
  const { vocab, signatures } = buildVocabularyFromRunsDir(runsDir);

  if (vocab.size === 0 || signatures.length === 0) return [];

  const queryVec = vectorizeSignature(querySignature, vocab);
  const results: SimilarRun[] = [];

  for (const { runId, signature } of signatures) {
    const vec = vectorizeSignature(signature, vocab);
    const score = cosineSimilarity(queryVec, vec);
    results.push({ run_id: runId, score, signature });
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit);
}
