import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface LicenseInfo {
  tier: 'free' | 'pro' | 'enterprise';
  org?: string;
  features: Set<string>;
  exp?: number;
}

interface LicensePayload {
  tier: 'pro' | 'enterprise';
  org?: string;
  features?: string[];
  exp?: number;
  iat?: number;
}

function getPublicKey(): string {
  // RS256 public key for license verification.
  // In production this would be replaced with the actual AgentCI signing key.
  // Read from env at call time (not module load time) to support testing.
  return process.env.AGENTCI_LICENSE_PUBLIC_KEY || '';
}

const FREE_LICENSE: LicenseInfo = {
  tier: 'free',
  features: new Set(),
};

let cachedLicense: LicenseInfo | null = null;

function base64UrlDecode(str: string): Buffer {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

function verifyJwt(token: string, publicKey: string): LicensePayload | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const headerJson = base64UrlDecode(parts[0]).toString('utf-8');
    const header = JSON.parse(headerJson);
    if (header.alg !== 'RS256') return null;

    const payloadJson = base64UrlDecode(parts[1]).toString('utf-8');
    const payload = JSON.parse(payloadJson) as LicensePayload;

    // Verify signature if public key is available
    if (publicKey) {
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(`${parts[0]}.${parts[1]}`);
      const valid = verifier.verify(publicKey, base64UrlDecode(parts[2]));
      if (!valid) return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Load license from .agentci/license file or AGENTCI_LICENSE_KEY env var.
 * Returns free tier if no valid license is found.
 */
export function loadLicense(agentciDir?: string): LicenseInfo {
  if (cachedLicense) return cachedLicense;

  let token: string | undefined;

  // Try file first
  if (agentciDir) {
    const licensePath = path.join(agentciDir, 'license');
    try {
      token = fs.readFileSync(licensePath, 'utf-8').trim();
    } catch {
      // No license file — that's fine
    }
  }

  // Fall back to env var
  if (!token) {
    token = process.env.AGENTCI_LICENSE_KEY?.trim();
  }

  if (!token) {
    cachedLicense = FREE_LICENSE;
    return FREE_LICENSE;
  }

  const payload = verifyJwt(token, getPublicKey());
  if (!payload) {
    if (process.env.AGENTCI_DEBUG) {
      console.error('[agentci] Invalid or malformed license token — falling back to free tier');
    }
    cachedLicense = FREE_LICENSE;
    return FREE_LICENSE;
  }

  // Check expiry
  if (payload.exp && Date.now() / 1000 > payload.exp) {
    if (process.env.AGENTCI_DEBUG) {
      console.error('[agentci] License expired — falling back to free tier');
    }
    cachedLicense = FREE_LICENSE;
    return FREE_LICENSE;
  }

  const license: LicenseInfo = {
    tier: payload.tier,
    org: payload.org,
    features: new Set(payload.features || []),
  };

  if (payload.exp) {
    license.exp = payload.exp;
  }

  cachedLicense = license;
  return license;
}

/**
 * Check if a specific feature is licensed.
 */
export function hasFeature(name: string, agentciDir?: string): boolean {
  const license = loadLicense(agentciDir);
  return license.features.has(name);
}

/**
 * Require a licensed feature. Throws with a clear upgrade message if not licensed.
 */
export function requireFeature(name: string, label: string, agentciDir?: string): void {
  if (!hasFeature(name, agentciDir)) {
    const err = new Error(
      `Feature "${label}" requires an AgentCI Pro license. Visit https://agentci.dev/pricing to upgrade.`
    );
    (err as Error & { code: string }).code = 'LICENSE_REQUIRED';
    throw err;
  }
}

/**
 * Clear the cached license (for testing).
 */
export function clearLicenseCache(): void {
  cachedLicense = null;
}
