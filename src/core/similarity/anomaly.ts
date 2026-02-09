import type { EffectSignature } from '../types.js';
import { buildVocabularyFromRunsDir, vectorizeSignature, cosineSimilarity } from './vectorize.js';

export interface AnomalyResult {
  is_anomaly: boolean;
  score: number;
  threshold: number;
  nearest_neighbors: Array<{ run_id: string; similarity: number }>;
}

/**
 * Detect whether a signature represents anomalous behavior compared to historical runs.
 * Uses average cosine similarity to K nearest neighbors.
 *
 * A low average similarity (below threshold) indicates the run is an outlier.
 */
export function detectAnomaly(
  signature: EffectSignature,
  runsDir: string,
  options: { threshold?: number; k?: number } = {},
): AnomalyResult {
  const threshold = options.threshold ?? 0.7;
  const k = options.k ?? 5;

  const { vocab, signatures } = buildVocabularyFromRunsDir(runsDir);

  if (vocab.size === 0 || signatures.length === 0) {
    return {
      is_anomaly: false,
      score: 1.0,
      threshold,
      nearest_neighbors: [],
    };
  }

  const queryVec = vectorizeSignature(signature, vocab);
  const similarities: Array<{ run_id: string; similarity: number }> = [];

  for (const { runId, signature: sig } of signatures) {
    const vec = vectorizeSignature(sig, vocab);
    const sim = cosineSimilarity(queryVec, vec);
    similarities.push({ run_id: runId, similarity: sim });
  }

  similarities.sort((a, b) => b.similarity - a.similarity);
  const nearest = similarities.slice(0, k);
  const avgSimilarity = nearest.length > 0 ? nearest.reduce((sum, n) => sum + n.similarity, 0) / nearest.length : 0;

  return {
    is_anomaly: avgSimilarity < threshold,
    score: avgSimilarity,
    threshold,
    nearest_neighbors: nearest,
  };
}
