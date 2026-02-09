import { requireFeature } from '../../core/license.js';

/**
 * ANNPack integration for fast approximate nearest-neighbor search.
 * Requires Pro license and ANNPack CLI to be installed.
 *
 * ANNPack is a static vector index format that uses:
 * - IVF (Inverted File Index) algorithm for fast search
 * - WASM decoder for client-side search
 * - HTTP Range requests for partial index loading
 *
 * This module provides the bridge between AgentCI's signature vectorization
 * and ANNPack's indexing/search capabilities.
 */

export function ensureAnnpack(agentciDir?: string): void {
  requireFeature('annpack', 'ANNPack Similarity Search', agentciDir);
}

/**
 * Build an ANNPack index from all runs in the runs directory.
 * Placeholder — requires ANNPack CLI to be available.
 */
export async function buildAnnpackIndex(
  _runsDir: string,
  _outPath: string,
  agentciDir?: string,
): Promise<void> {
  ensureAnnpack(agentciDir);

  // ANNPack is alpha-stage. This is the integration point where we would:
  // 1. Vectorize all signatures in runsDir
  // 2. Write vectors to a temp JSONL file
  // 3. Call `annpack-build` CLI to create the index
  // 4. Move the index to outPath
  throw new Error(
    'ANNPack integration is not yet available. ' +
    'ANNPack is in alpha stage. Use `agentci similar` for brute-force search in the meantime.',
  );
}

/**
 * Search an ANNPack index for similar vectors.
 * Placeholder — requires ANNPack JS client.
 */
export async function searchAnnpack(
  _queryVector: Float64Array,
  _indexPath: string,
  _k: number,
  agentciDir?: string,
): Promise<Array<{ id: string; score: number }>> {
  ensureAnnpack(agentciDir);

  throw new Error(
    'ANNPack integration is not yet available. ' +
    'Use `agentci similar` for brute-force search in the meantime.',
  );
}
