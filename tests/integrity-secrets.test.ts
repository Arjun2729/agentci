import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  generateSecret,
  writeSecret,
  loadSecret,
  computeTraceHmac,
  writeTraceChecksum,
  verifyTraceIntegrity,
} from '../src/core/integrity';

describe('secret key management', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-secrets-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('generateSecret returns a 128-char hex string', () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[a-f0-9]{128}$/);
  });

  it('generateSecret produces unique values', () => {
    const s1 = generateSecret();
    const s2 = generateSecret();
    expect(s1).not.toBe(s2);
  });

  it('writeSecret creates a secret file with restricted permissions', () => {
    const agentciDir = path.join(tmpDir, '.agentci');
    fs.mkdirSync(agentciDir, { recursive: true });
    const secretPath = writeSecret(agentciDir);
    expect(fs.existsSync(secretPath)).toBe(true);
    const content = fs.readFileSync(secretPath, 'utf8');
    expect(content).toMatch(/^[a-f0-9]{128}$/);
  });

  it('loadSecret reads the project secret when it exists', () => {
    const agentciDir = path.join(tmpDir, '.agentci');
    fs.mkdirSync(agentciDir, { recursive: true });
    writeSecret(agentciDir);
    const secret = loadSecret(tmpDir, 'any-run-id');
    expect(secret).toMatch(/^[a-f0-9]{128}$/);
  });

  it('loadSecret falls back to legacy key when no secret file exists', () => {
    const secret = loadSecret(tmpDir, 'my-run');
    expect(secret).toBe('agentci-legacy:my-run');
  });
});

describe('integrity with project secret', () => {
  let tmpDir: string;
  let tracePath: string;
  let secret: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-intsec-'));
    tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(
      tracePath,
      '{"id":"1","timestamp":1000,"run_id":"run-1","type":"lifecycle","data":{"stage":"start"}}\n',
      'utf8',
    );
    secret = generateSecret();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('HMAC with secret differs from HMAC with legacy key', () => {
    const hmacWithSecret = computeTraceHmac(tracePath, 'run-1', secret);
    const hmacLegacy = computeTraceHmac(tracePath, 'run-1');
    expect(hmacWithSecret).not.toBe(hmacLegacy);
  });

  it('verify succeeds with correct secret', () => {
    writeTraceChecksum(tracePath, 'run-1', secret);
    const result = verifyTraceIntegrity(tracePath, 'run-1', secret);
    expect(result.valid).toBe(true);
    expect(result.details).toContain('project secret');
  });

  it('verify fails with wrong secret', () => {
    writeTraceChecksum(tracePath, 'run-1', secret);
    const wrongSecret = generateSecret();
    const result = verifyTraceIntegrity(tracePath, 'run-1', wrongSecret);
    expect(result.valid).toBe(false);
    expect(result.details).toContain('modified');
  });

  it('checksum file records key_source as project-secret', () => {
    const checksumPath = writeTraceChecksum(tracePath, 'run-1', secret);
    const checksum = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
    expect(checksum.key_source).toBe('project-secret');
  });

  it('checksum file records key_source as legacy when no secret provided', () => {
    const checksumPath = writeTraceChecksum(tracePath, 'run-1');
    const checksum = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
    expect(checksum.key_source).toBe('legacy');
  });
});
