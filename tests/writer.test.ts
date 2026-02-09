import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { TraceWriter } from '../src/recorder/writer';
import { TraceEvent } from '../src/core/types';

function makeEvent(id: string): TraceEvent {
  return {
    id,
    timestamp: Date.now(),
    run_id: 'test-run',
    type: 'lifecycle',
    data: { stage: 'start' },
  };
}

describe('TraceWriter (buffered)', () => {
  let tmpDir: string;
  let tracePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-writer-'));
    tracePath = path.join(tmpDir, 'trace.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('buffers events and flushes on close', () => {
    const state = { bypass: false };
    const writer = new TraceWriter({
      runDir: tmpDir,
      tracePath,
      runId: 'test',
      originals: {
        appendFileSync: fs.appendFileSync,
        mkdirSync: fs.mkdirSync,
        writeFileSync: fs.writeFileSync,
      },
      state,
      bufferSize: 100, // large buffer so events stay buffered
      flushIntervalMs: 60000, // long interval
    });

    writer.write(makeEvent('1'));
    writer.write(makeEvent('2'));
    writer.write(makeEvent('3'));

    // Events should be buffered, file should be empty or minimal
    writer.close();

    const content = fs.readFileSync(tracePath, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(3);
  });

  it('auto-flushes when buffer is full', () => {
    const state = { bypass: false };
    const writer = new TraceWriter({
      runDir: tmpDir,
      tracePath,
      runId: 'test',
      originals: {
        appendFileSync: fs.appendFileSync,
        mkdirSync: fs.mkdirSync,
        writeFileSync: fs.writeFileSync,
      },
      state,
      bufferSize: 3,
      flushIntervalMs: 60000,
    });

    writer.write(makeEvent('1'));
    writer.write(makeEvent('2'));
    writer.write(makeEvent('3'));

    // Buffer should have auto-flushed at size 3
    const content = fs.readFileSync(tracePath, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(3);

    writer.close();
  });

  it('sets bypass during flush operations', () => {
    const state = { bypass: false };
    let wasBypassedDuringWrite = false;
    const customAppend: typeof fs.appendFileSync = function (...args: any[]) {
      wasBypassedDuringWrite = state.bypass;
      return (fs.appendFileSync as any)(...args);
    };

    const writer = new TraceWriter({
      runDir: tmpDir,
      tracePath,
      runId: 'test',
      originals: {
        appendFileSync: customAppend,
        mkdirSync: fs.mkdirSync,
        writeFileSync: fs.writeFileSync,
      },
      state,
      bufferSize: 1,
      flushIntervalMs: 60000,
    });

    writer.write(makeEvent('1'));
    expect(wasBypassedDuringWrite).toBe(true);
    expect(state.bypass).toBe(false); // reset after flush

    writer.close();
  });

  it('ignores writes after close', () => {
    const state = { bypass: false };
    const writer = new TraceWriter({
      runDir: tmpDir,
      tracePath,
      runId: 'test',
      originals: {
        appendFileSync: fs.appendFileSync,
        mkdirSync: fs.mkdirSync,
        writeFileSync: fs.writeFileSync,
      },
      state,
      bufferSize: 100,
      flushIntervalMs: 60000,
    });

    writer.write(makeEvent('1'));
    writer.close();
    writer.write(makeEvent('2')); // should be ignored

    const content = fs.readFileSync(tracePath, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(1);
  });
});
