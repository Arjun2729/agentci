/**
 * Property-based / fuzz tests for parsers and integrity verification.
 *
 * These tests feed randomly generated and malformed inputs to ensure
 * no crashes, hangs, or unexpected exceptions.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { readJsonl } from '../src/core/trace/read_jsonl';
import { verifyTraceIntegrity, computeTraceHmac, writeTraceChecksum } from '../src/core/integrity';

function randomBytes(len: number): Buffer {
  const buf = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    buf[i] = Math.floor(Math.random() * 256);
  }
  return buf;
}

function randomString(len: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789{}[]":,\n\r\t \\';
  let s = '';
  for (let i = 0; i < len; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}

describe('JSONL parser fuzz tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-fuzz-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('handles empty file', () => {
    const p = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(p, '', 'utf8');
    const events = readJsonl(p);
    expect(events).toEqual([]);
  });

  it('handles file with only whitespace and newlines', () => {
    const p = path.join(tmpDir, 'whitespace.jsonl');
    fs.writeFileSync(p, '   \n\n  \n  \t  \n', 'utf8');
    const events = readJsonl(p);
    expect(events).toEqual([]);
  });

  it('handles file with only invalid JSON lines', () => {
    const p = path.join(tmpDir, 'invalid.jsonl');
    const lines = Array.from({ length: 20 }, () => randomString(50));
    fs.writeFileSync(p, lines.join('\n'), 'utf8');
    // Should not throw — invalid lines are silently skipped (except last line)
    const events = readJsonl(p);
    expect(Array.isArray(events)).toBe(true);
  });

  it('handles mixed valid and invalid lines', () => {
    const p = path.join(tmpDir, 'mixed.jsonl');
    const validLine = JSON.stringify({
      id: 'test-1',
      timestamp: Date.now(),
      run_id: 'fuzz-run',
      type: 'effect',
      data: { category: 'fs_write' },
    });
    const content = ['garbage{{{', validLine, '???not json???', validLine, 'truncated{"id":'].join('\n');
    fs.writeFileSync(p, content, 'utf8');
    const events = readJsonl(p);
    expect(events.length).toBe(2);
  });

  it('handles binary content without crashing', () => {
    const p = path.join(tmpDir, 'binary.jsonl');
    fs.writeFileSync(p, randomBytes(1024));
    // Should not throw
    const events = readJsonl(p);
    expect(Array.isArray(events)).toBe(true);
  });

  it('handles extremely long lines', () => {
    const p = path.join(tmpDir, 'longline.jsonl');
    const longValue = 'x'.repeat(100_000);
    const line = JSON.stringify({
      id: 'long-1',
      timestamp: Date.now(),
      run_id: 'fuzz-run',
      type: 'effect',
      data: { value: longValue },
    });
    fs.writeFileSync(p, line + '\n', 'utf8');
    const events = readJsonl(p);
    expect(events.length).toBe(1);
  });

  it('handles many empty lines interspersed with valid events', () => {
    const p = path.join(tmpDir, 'sparse.jsonl');
    const validLine = JSON.stringify({
      id: 'sparse-1',
      timestamp: Date.now(),
      run_id: 'fuzz-run',
      type: 'lifecycle',
      data: { stage: 'start' },
    });
    const lines = Array.from({ length: 100 }, (_, i) => (i % 10 === 0 ? validLine : ''));
    fs.writeFileSync(p, lines.join('\n'), 'utf8');
    const events = readJsonl(p);
    expect(events.length).toBe(10);
  });

  it('handles null bytes in content', () => {
    const p = path.join(tmpDir, 'nullbytes.jsonl');
    fs.writeFileSync(p, '\0\0\n{"type":"effect"}\n\0', 'utf8');
    const events = readJsonl(p);
    // Should not throw
    expect(Array.isArray(events)).toBe(true);
  });

  it('handles JSON objects without required type field', () => {
    const p = path.join(tmpDir, 'notype.jsonl');
    const lines = [
      '{"id":"1","timestamp":123}',
      '{"type":"effect","id":"2","timestamp":456,"run_id":"r","data":{}}',
      '{"name":"not-a-trace-event"}',
      '{}',
    ].join('\n');
    fs.writeFileSync(p, lines, 'utf8');
    const events = readJsonl(p);
    // Only the line with a "type" field should be parsed
    expect(events.length).toBe(1);
    expect(events[0].type).toBe('effect');
  });
});

describe('HMAC integrity fuzz tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-hmac-fuzz-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('rejects corrupted checksum JSON', () => {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(tracePath, '{"type":"effect"}\n', 'utf8');
    const checksumPath = path.join(tmpDir, 'trace.checksum');
    fs.writeFileSync(checksumPath, 'not-valid-json!!!', 'utf8');

    const result = verifyTraceIntegrity(tracePath, 'test-run', 'test-secret');
    expect(result.valid).toBe(false);
    expect(result.details).toContain('Invalid checksum file');
  });

  it('rejects checksum with wrong run_id', () => {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(tracePath, '{"type":"effect"}\n', 'utf8');
    const checksumPath = path.join(tmpDir, 'trace.checksum');
    fs.writeFileSync(
      checksumPath,
      JSON.stringify({
        algorithm: 'hmac-sha256',
        hmac: 'deadbeef',
        trace_file: 'trace.jsonl',
        run_id: 'wrong-run',
      }),
      'utf8',
    );

    const result = verifyTraceIntegrity(tracePath, 'correct-run', 'test-secret');
    expect(result.valid).toBe(false);
    expect(result.details).toContain('Run ID mismatch');
  });

  it('rejects tampered trace content', () => {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    const runId = 'tamper-test';
    const secret = 'test-secret-key';
    fs.writeFileSync(tracePath, '{"type":"effect","data":{}}\n', 'utf8');

    // Create a valid checksum
    const runDir = path.join(tmpDir, '.agentci', 'runs', runId);
    fs.mkdirSync(runDir, { recursive: true });
    const realTrace = path.join(runDir, 'trace.jsonl');
    fs.writeFileSync(realTrace, '{"type":"effect","data":{}}\n', 'utf8');
    writeTraceChecksum(realTrace, runId, secret);

    // Tamper with the trace
    fs.writeFileSync(realTrace, '{"type":"effect","data":{"tampered":true}}\n', 'utf8');

    const result = verifyTraceIntegrity(realTrace, runId, secret);
    expect(result.valid).toBe(false);
    expect(result.details).toContain('HMAC mismatch');
  });

  it('handles empty trace file for HMAC computation', () => {
    const tracePath = path.join(tmpDir, 'empty-trace.jsonl');
    fs.writeFileSync(tracePath, '', 'utf8');
    // Should not throw
    const hmac = computeTraceHmac(tracePath, 'test-run', 'secret');
    expect(typeof hmac).toBe('string');
    expect(hmac.length).toBe(64); // SHA-256 hex = 64 chars
  });

  it('produces different HMACs for different secrets', () => {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(tracePath, '{"type":"effect"}\n', 'utf8');
    const hmac1 = computeTraceHmac(tracePath, 'run', 'secret-1');
    const hmac2 = computeTraceHmac(tracePath, 'run', 'secret-2');
    expect(hmac1).not.toBe(hmac2);
  });

  it('handles checksum with truncated HMAC hex', () => {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    fs.writeFileSync(tracePath, '{"type":"effect"}\n', 'utf8');
    const checksumPath = path.join(tmpDir, 'trace.checksum');
    fs.writeFileSync(
      checksumPath,
      JSON.stringify({
        algorithm: 'hmac-sha256',
        hmac: 'ab', // Truncated — only 1 byte instead of 32
        trace_file: 'trace.jsonl',
        run_id: 'test-run',
      }),
      'utf8',
    );

    const result = verifyTraceIntegrity(tracePath, 'test-run', 'secret');
    expect(result.valid).toBe(false);
  });
});
