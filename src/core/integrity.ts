/**
 * Trace integrity verification using HMAC-SHA256.
 *
 * Computes a rolling HMAC over trace events and writes/verifies
 * a checksum file alongside the trace.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const ALGORITHM = 'sha256';
const CHECKSUM_FILENAME = 'trace.checksum';

/**
 * Compute HMAC-SHA256 of the trace file contents.
 * Uses a deterministic key derived from the run ID to detect tampering.
 */
export function computeTraceHmac(tracePath: string, runId: string): string {
  const content = fs.readFileSync(tracePath, 'utf8');
  const hmac = crypto.createHmac(ALGORITHM, `agentci:${runId}`);
  hmac.update(content);
  return hmac.digest('hex');
}

/**
 * Write a checksum file next to the trace file.
 */
export function writeTraceChecksum(tracePath: string, runId: string): string {
  const hmac = computeTraceHmac(tracePath, runId);
  const checksumPath = path.join(path.dirname(tracePath), CHECKSUM_FILENAME);
  const payload = JSON.stringify({
    algorithm: `hmac-${ALGORITHM}`,
    hmac,
    trace_file: path.basename(tracePath),
    run_id: runId,
    computed_at: new Date().toISOString(),
  }, null, 2);
  fs.writeFileSync(checksumPath, payload, 'utf8');
  return checksumPath;
}

/**
 * Verify a trace file against its checksum file.
 * Returns { valid, details }.
 */
export function verifyTraceIntegrity(tracePath: string, runId: string): { valid: boolean; details: string } {
  const checksumPath = path.join(path.dirname(tracePath), CHECKSUM_FILENAME);

  if (!fs.existsSync(checksumPath)) {
    return { valid: false, details: `Checksum file not found: ${checksumPath}` };
  }

  let stored: { algorithm: string; hmac: string; trace_file: string; run_id: string };
  try {
    stored = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
  } catch (err) {
    return { valid: false, details: `Invalid checksum file: ${err}` };
  }

  if (stored.run_id !== runId) {
    return { valid: false, details: `Run ID mismatch: expected ${runId}, got ${stored.run_id}` };
  }

  const computed = computeTraceHmac(tracePath, runId);
  if (computed !== stored.hmac) {
    return { valid: false, details: 'HMAC mismatch — trace file has been modified' };
  }

  return { valid: true, details: 'Trace integrity verified' };
}
