import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { computeTraceHmac, writeTraceChecksum, verifyTraceIntegrity } from '../src/core/integrity';

describe('trace integrity', () => {
  let tmpDir: string;
  let tracePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-integrity-'));
    tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(
      tracePath,
      '{"id":"1","timestamp":1000,"run_id":"test-run","type":"lifecycle","data":{"stage":"start"}}\n' +
        '{"id":"2","timestamp":2000,"run_id":"test-run","type":"lifecycle","data":{"stage":"stop"}}\n',
      'utf8'
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('computes a deterministic HMAC for the same content', () => {
    const hmac1 = computeTraceHmac(tracePath, 'test-run');
    const hmac2 = computeTraceHmac(tracePath, 'test-run');
    expect(hmac1).toBe(hmac2);
    expect(hmac1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different HMACs for different run IDs', () => {
    const hmac1 = computeTraceHmac(tracePath, 'run-a');
    const hmac2 = computeTraceHmac(tracePath, 'run-b');
    expect(hmac1).not.toBe(hmac2);
  });

  it('writes a checksum file with correct structure', () => {
    const checksumPath = writeTraceChecksum(tracePath, 'test-run');
    expect(fs.existsSync(checksumPath)).toBe(true);

    const content = JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
    expect(content.algorithm).toBe('hmac-sha256');
    expect(content.hmac).toMatch(/^[a-f0-9]{64}$/);
    expect(content.trace_file).toBe('trace.jsonl');
    expect(content.run_id).toBe('test-run');
    expect(content.computed_at).toBeTruthy();
  });

  it('verifies an unmodified trace file', () => {
    writeTraceChecksum(tracePath, 'test-run');
    const result = verifyTraceIntegrity(tracePath, 'test-run');
    expect(result.valid).toBe(true);
    expect(result.details).toContain('verified');
  });

  it('detects trace file modification', () => {
    writeTraceChecksum(tracePath, 'test-run');

    // Tamper with the trace file
    fs.appendFileSync(tracePath, '{"id":"3","timestamp":3000,"run_id":"test-run","type":"lifecycle","data":{"stage":"error"}}\n');

    const result = verifyTraceIntegrity(tracePath, 'test-run');
    expect(result.valid).toBe(false);
    expect(result.details).toContain('modified');
  });

  it('detects missing checksum file', () => {
    const result = verifyTraceIntegrity(tracePath, 'test-run');
    expect(result.valid).toBe(false);
    expect(result.details).toContain('not found');
  });

  it('detects run ID mismatch', () => {
    writeTraceChecksum(tracePath, 'test-run');
    const result = verifyTraceIntegrity(tracePath, 'different-run');
    expect(result.valid).toBe(false);
    expect(result.details).toContain('mismatch');
  });
});
