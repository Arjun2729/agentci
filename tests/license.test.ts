import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadLicense, hasFeature, requireFeature, clearLicenseCache } from '../src/core/license.js';

// Generate a test RSA key pair for JWT signing/verification
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function base64UrlEncode(data: Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createTestJwt(payload: Record<string, unknown>, key: string = privateKey): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${body}`);
  const signature = base64UrlEncode(signer.sign(key));
  return `${header}.${body}.${signature}`;
}

describe('license', () => {
  let tmpDir: string;

  beforeEach(() => {
    clearLicenseCache();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-license-'));
    // Set the public key for verification
    process.env.AGENTCI_LICENSE_PUBLIC_KEY = publicKey;
    delete process.env.AGENTCI_LICENSE_KEY;
  });

  afterEach(() => {
    clearLicenseCache();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.AGENTCI_LICENSE_PUBLIC_KEY;
    delete process.env.AGENTCI_LICENSE_KEY;
  });

  it('returns free tier when no license file exists', () => {
    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('free');
    expect(license.features.size).toBe(0);
  });

  it('loads valid JWT license from file', () => {
    const token = createTestJwt({
      tier: 'pro',
      org: 'test-org',
      features: ['remote', 'annpack', 'anomaly'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('pro');
    expect(license.org).toBe('test-org');
    expect(license.features.has('remote')).toBe(true);
    expect(license.features.has('annpack')).toBe(true);
    expect(license.features.has('anomaly')).toBe(true);
  });

  it('loads license from AGENTCI_LICENSE_KEY env var', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    process.env.AGENTCI_LICENSE_KEY = token;

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('pro');
    expect(license.features.has('remote')).toBe(true);
  });

  it('returns free tier for expired JWT', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) - 3600, // expired 1 hour ago
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('free');
    expect(license.features.size).toBe(0);
  });

  it('returns free tier for malformed JWT', () => {
    fs.writeFileSync(path.join(tmpDir, 'license'), 'not-a-jwt');

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('free');
  });

  it('returns free tier for JWT with wrong algorithm', () => {
    // Manually craft a JWT with alg: HS256 (not RS256)
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = base64UrlEncode(JSON.stringify({ tier: 'pro', features: ['remote'] }));
    const fakeSig = base64UrlEncode('fake-signature');
    const token = `${header}.${body}.${fakeSig}`;
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('free');
  });

  it('returns free tier for tampered JWT payload', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    // Tamper with payload (change tier to enterprise)
    const parts = token.split('.');
    const tamperedPayload = base64UrlEncode(JSON.stringify({ tier: 'enterprise', features: ['remote', 'annpack'] }));
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    fs.writeFileSync(path.join(tmpDir, 'license'), tampered);

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('free'); // Signature verification fails
  });

  it('hasFeature returns true for licensed features', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote', 'annpack'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    expect(hasFeature('remote', tmpDir)).toBe(true);
    expect(hasFeature('annpack', tmpDir)).toBe(true);
    expect(hasFeature('nonexistent', tmpDir)).toBe(false);
  });

  it('requireFeature throws for missing feature', () => {
    expect(() => requireFeature('remote', 'Remote Control Plane', tmpDir)).toThrow(/requires an AgentCI Pro license/);
  });

  it('requireFeature passes for licensed feature', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    expect(() => requireFeature('remote', 'Remote Control Plane', tmpDir)).not.toThrow();
  });

  it('caches license after first load', () => {
    const token = createTestJwt({
      tier: 'pro',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), token);

    const first = loadLicense(tmpDir);
    // Delete the file — cached result should still work
    fs.unlinkSync(path.join(tmpDir, 'license'));
    const second = loadLicense(tmpDir);

    expect(first).toBe(second); // Same reference (cached)
    expect(second.tier).toBe('pro');
  });

  it('file takes precedence over env var', () => {
    const fileToken = createTestJwt({
      tier: 'pro',
      org: 'file-org',
      features: ['remote'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const envToken = createTestJwt({
      tier: 'enterprise',
      org: 'env-org',
      features: ['remote', 'annpack'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    fs.writeFileSync(path.join(tmpDir, 'license'), fileToken);
    process.env.AGENTCI_LICENSE_KEY = envToken;

    const license = loadLicense(tmpDir);
    expect(license.tier).toBe('pro');
    expect(license.org).toBe('file-org');
  });
});
