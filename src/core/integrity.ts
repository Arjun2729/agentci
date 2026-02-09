/**
 * Trace integrity verification using HMAC-SHA256.
 *
 * Uses a per-project secret key (generated at `agentci adopt` time)
 * to compute HMACs over trace contents. The secret is stored in
 * `.agentci/secret` and must never be committed to version control.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const ALGORITHM = 'sha256';
const CHECKSUM_FILENAME = 'trace.checksum';
const SIGNATURE_CHECKSUM_FILENAME = 'signature.checksum';
const SECRET_FILENAME = 'secret';

/**
 * Generate a cryptographically random secret key for HMAC signing.
 * Returns the hex-encoded secret (64 bytes = 128 hex chars).
 */
export function generateSecret(): string {
  return crypto.randomBytes(64).toString('hex');
}

/**
 * Write a secret key file to the .agentci directory.
 * Sets permissions to 0o600 (owner-only read/write).
 */
export function writeSecret(agentciDir: string): string {
  const secret = generateSecret();
  const secretPath = path.join(agentciDir, SECRET_FILENAME);
  fs.writeFileSync(secretPath, secret, { encoding: 'utf8', mode: 0o600 });
  // Verify permissions were actually applied (may fail on FAT/NTFS)
  try {
    const stat = fs.statSync(secretPath);
    const mode = stat.mode & 0o777;
    if (mode !== 0o600) {
      // eslint-disable-next-line no-console
      console.error(
        `WARNING: Secret file has incorrect permissions (0o${mode.toString(8)}). ` +
          'Expected 0o600. Your filesystem may not support POSIX permissions.',
      );
    }
  } catch {
    // stat failed — not critical, secret was still written
  }
  return secretPath;
}

/**
 * Load the secret key from the .agentci directory.
 * Falls back to a run-id-derived key if no secret file exists (legacy mode).
 */
export function loadSecret(workspaceRoot: string, runId: string): string {
  const secretPath = path.join(workspaceRoot, '.agentci', SECRET_FILENAME);
  if (fs.existsSync(secretPath)) {
    return fs.readFileSync(secretPath, 'utf8').trim();
  }
  // Legacy fallback for traces created before secret key was introduced.
  // This is weaker — the runId is public — but allows verifying old traces.
  return `agentci-legacy:${runId}`;
}

/**
 * Compute HMAC-SHA256 of the trace file contents using a proper secret key.
 */
export function computeTraceHmac(tracePath: string, runId: string, secret?: string): string {
  const key = secret ?? `agentci-legacy:${runId}`;
  const content = fs.readFileSync(tracePath, 'utf8');
  const hmac = crypto.createHmac(ALGORITHM, key);
  hmac.update(content);
  return hmac.digest('hex');
}

function computeFileHmac(filePath: string, runId: string, secret?: string): string {
  const key = secret ?? `agentci-legacy:${runId}`;
  const content = fs.readFileSync(filePath, 'utf8');
  const hmac = crypto.createHmac(ALGORITHM, key);
  hmac.update(content);
  return hmac.digest('hex');
}

/**
 * Write a checksum file next to the trace file.
 */
export function writeTraceChecksum(tracePath: string, runId: string, secret?: string): string {
  const key = secret ?? loadSecret(path.dirname(path.dirname(path.dirname(tracePath))), runId);
  const hmac = computeTraceHmac(tracePath, runId, key);
  const checksumPath = path.join(path.dirname(tracePath), CHECKSUM_FILENAME);
  const payload = JSON.stringify(
    {
      algorithm: `hmac-${ALGORITHM}`,
      hmac,
      trace_file: path.basename(tracePath),
      run_id: runId,
      key_source: secret ? 'project-secret' : 'legacy',
      computed_at: new Date().toISOString(),
    },
    null,
    2,
  );
  fs.writeFileSync(checksumPath, payload, { encoding: 'utf8', mode: 0o600 });
  return checksumPath;
}

export function writeSignatureChecksum(signaturePath: string, runId: string, secret?: string): string {
  const key = secret ?? loadSecret(path.dirname(path.dirname(path.dirname(signaturePath))), runId);
  const hmac = computeFileHmac(signaturePath, runId, key);
  const checksumPath = path.join(path.dirname(signaturePath), SIGNATURE_CHECKSUM_FILENAME);
  const payload = JSON.stringify(
    {
      algorithm: `hmac-${ALGORITHM}`,
      hmac,
      signature_file: path.basename(signaturePath),
      run_id: runId,
      key_source: secret ? 'project-secret' : 'legacy',
      computed_at: new Date().toISOString(),
    },
    null,
    2,
  );
  fs.writeFileSync(checksumPath, payload, { encoding: 'utf8', mode: 0o600 });
  return checksumPath;
}

/**
 * Verify a trace file against its checksum file.
 * Uses timing-safe comparison to prevent side-channel attacks.
 */
export function verifyTraceIntegrity(
  tracePath: string,
  runId: string,
  secret?: string,
): { valid: boolean; details: string } {
  const checksumPath = path.join(path.dirname(tracePath), CHECKSUM_FILENAME);

  if (!fs.existsSync(checksumPath)) {
    return { valid: false, details: `Checksum file not found: ${checksumPath}` };
  }

  let stored: { algorithm: string; hmac: string; trace_file: string; run_id: string; key_source?: string };
  try {
    stored = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
  } catch (err) {
    return { valid: false, details: `Invalid checksum file: ${err}` };
  }

  if (stored.run_id !== runId) {
    return { valid: false, details: `Run ID mismatch: expected ${runId}, got ${stored.run_id}` };
  }

  const key = secret ?? loadSecret(path.dirname(path.dirname(path.dirname(tracePath))), runId);
  const computed = computeTraceHmac(tracePath, runId, key);

  // Timing-safe comparison to prevent side-channel attacks.
  // Both buffers should always be 32 bytes (SHA-256 output) but we handle
  // length mismatches without leaking timing information.
  const computedBuf = Buffer.from(computed, 'hex');
  const storedBuf = Buffer.from(stored.hmac, 'hex');
  if (computedBuf.length !== storedBuf.length) {
    // Do a dummy constant-time comparison so the timing is identical to the equal-length case
    crypto.timingSafeEqual(computedBuf, Buffer.alloc(computedBuf.length));
    return { valid: false, details: 'HMAC mismatch — trace file has been modified' };
  }
  if (!crypto.timingSafeEqual(computedBuf, storedBuf)) {
    return { valid: false, details: 'HMAC mismatch — trace file has been modified' };
  }

  const keyInfo = stored.key_source === 'project-secret' ? ' (project secret)' : ' (legacy key)';
  return { valid: true, details: `Trace integrity verified${keyInfo}` };
}

export function verifySignatureIntegrity(
  signaturePath: string,
  runId: string,
  secret?: string,
): { valid: boolean; details: string } {
  const checksumPath = path.join(path.dirname(signaturePath), SIGNATURE_CHECKSUM_FILENAME);
  if (!fs.existsSync(checksumPath)) {
    return { valid: false, details: `Checksum file not found: ${checksumPath}` };
  }

  let stored: { algorithm: string; hmac: string; signature_file: string; run_id: string; key_source?: string };
  try {
    stored = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
  } catch (err) {
    return { valid: false, details: `Invalid checksum file: ${err}` };
  }

  if (stored.run_id !== runId) {
    return { valid: false, details: `Run ID mismatch: expected ${runId}, got ${stored.run_id}` };
  }

  const key = secret ?? loadSecret(path.dirname(path.dirname(path.dirname(signaturePath))), runId);
  const computed = computeFileHmac(signaturePath, runId, key);

  const computedBuf = Buffer.from(computed, 'hex');
  const storedBuf = Buffer.from(stored.hmac, 'hex');
  if (computedBuf.length !== storedBuf.length) {
    crypto.timingSafeEqual(computedBuf, Buffer.alloc(computedBuf.length));
    return { valid: false, details: 'HMAC mismatch — signature file has been modified' };
  }
  if (!crypto.timingSafeEqual(computedBuf, storedBuf)) {
    return { valid: false, details: 'HMAC mismatch — signature file has been modified' };
  }

  const keyInfo = stored.key_source === 'project-secret' ? ' (project secret)' : ' (legacy key)';
  return { valid: true, details: `Signature integrity verified${keyInfo}` };
}
