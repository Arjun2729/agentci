import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { generateApiKey, addApiKey, hashApiKey, lookupApiKey } from '../src/pro/remote/keygen.js';
import { clearLicenseCache } from '../src/core/license.js';

// Generate a test RSA key pair for license
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function base64UrlEncode(data: Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createTestJwt(payload: Record<string, unknown>): string {
  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload));
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${body}`);
  const signature = base64UrlEncode(signer.sign(privateKey));
  return `${header}.${body}.${signature}`;
}

function httpRequest(options: http.RequestOptions & { body?: string }): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => {
        data += chunk.toString();
      });
      res.on('end', () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

describe('remote control plane', () => {
  let tmpDir: string;
  let dataDir: string;
  let keysFile: string;
  let apiKey: string;
  let server: http.Server;
  let port: number;

  beforeEach(async () => {
    clearLicenseCache();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-remote-'));
    dataDir = path.join(tmpDir, 'data');
    keysFile = path.join(tmpDir, 'keys', 'api-keys.json');

    // Create a valid Pro license
    const licenseToken = createTestJwt({
      tier: 'pro',
      features: ['remote', 'annpack', 'anomaly'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const agentciDir = path.join(tmpDir, '.agentci');
    fs.mkdirSync(agentciDir, { recursive: true });
    fs.writeFileSync(path.join(agentciDir, 'license'), licenseToken);

    process.env.AGENTCI_LICENSE_PUBLIC_KEY = publicKey;

    // Generate API key
    apiKey = generateApiKey();
    addApiKey(keysFile, apiKey, 'test-team', 'test-key');

    // Start server
    const { serveRemote } = await import('../src/pro/remote/server.js');
    server = serveRemote(dataDir, 0, keysFile, agentciDir);

    // Wait for server to start and get the port
    await new Promise<void>((resolve) => {
      server.on('listening', () => {
        const addr = server.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterEach(async () => {
    clearLicenseCache();
    delete process.env.AGENTCI_LICENSE_PUBLIC_KEY;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('push run with valid API key returns 200', async () => {
    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/push',
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        run_id: 'test-run-001',
        signature: { meta: { signature_version: '1.0' }, effects: {} },
        findings: [],
      }),
    });

    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('ok');
    expect(body.run_id).toBe('test-run-001');
  });

  it('push without API key returns 401', async () => {
    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/push',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        run_id: 'test-run',
        signature: {},
        findings: [],
      }),
    });

    expect(res.status).toBe(401);
  });

  it('push with invalid API key returns 403', async () => {
    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/push',
      method: 'POST',
      headers: {
        Authorization: 'Bearer agentci-invalidkey',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        run_id: 'test-run',
        signature: {},
        findings: [],
      }),
    });

    expect(res.status).toBe(403);
  });

  it('list runs returns pushed runs', async () => {
    // Push a run first
    await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/push',
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        run_id: 'listed-run',
        signature: { meta: {}, effects: {} },
        findings: [],
      }),
    });

    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/runs',
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}` },
    });

    expect(res.status).toBe(200);
    const runs = JSON.parse(res.body);
    expect(Array.isArray(runs)).toBe(true);
    expect(runs.some((r: { run_id: string }) => r.run_id === 'listed-run')).toBe(true);
  });

  it('get run detail returns signature and findings', async () => {
    const testSig = { meta: { signature_version: '1.0' }, effects: { fs_writes: ['test.ts'] } };

    await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/push',
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        run_id: 'detail-run',
        signature: testSig,
        findings: [{ severity: 'WARN', message: 'test finding' }],
      }),
    });

    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/api/runs/detail-run',
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}` },
    });

    expect(res.status).toBe(200);
    const detail = JSON.parse(res.body);
    expect(detail.run_id).toBe('detail-run');
    expect(detail.signature.effects.fs_writes).toEqual(['test.ts']);
    expect(detail.findings.length).toBe(1);
  });

  it('healthz requires no auth', async () => {
    const res = await httpRequest({
      hostname: 'localhost',
      port,
      path: '/healthz',
      method: 'GET',
    });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).status).toBe('ok');
  });
});

describe('keygen', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-keygen-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('generates keys with agentci- prefix', () => {
    const key = generateApiKey();
    expect(key.startsWith('agentci-')).toBe(true);
    expect(key.length).toBe(8 + 64); // prefix + 32 bytes hex
  });

  it('hashes keys deterministically', () => {
    const key = generateApiKey();
    expect(hashApiKey(key)).toBe(hashApiKey(key));
  });

  it('looks up stored keys', () => {
    const keysFile = path.join(tmpDir, 'keys.json');
    const key = generateApiKey();
    addApiKey(keysFile, key, 'team-1', 'dev-key');

    const entry = lookupApiKey(keysFile, key);
    expect(entry).not.toBeNull();
    expect(entry!.team_id).toBe('team-1');
    expect(entry!.name).toBe('dev-key');
  });

  it('returns null for unknown keys', () => {
    const keysFile = path.join(tmpDir, 'keys.json');
    const key = generateApiKey();
    addApiKey(keysFile, key, 'team-1', 'dev-key');

    expect(lookupApiKey(keysFile, 'agentci-unknown')).toBeNull();
  });
});
