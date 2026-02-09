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

describe('TraceWriter rate limiting', () => {
  let tmpDir: string;
  let tracePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-rl-'));
    tracePath = path.join(tmpDir, 'trace.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('drops events when rate limit is exceeded', () => {
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
      bufferSize: 1000,
      flushIntervalMs: 60000,
      maxEventsPerSecond: 5,
    });

    // Write 10 events — only 5 should be accepted
    for (let i = 0; i < 10; i++) {
      writer.write(makeEvent(`evt-${i}`));
    }
    writer.close();

    const content = fs.readFileSync(tracePath, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(5);
  });

  it('tracks totalDropped in metrics', () => {
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
      bufferSize: 1000,
      flushIntervalMs: 60000,
      maxEventsPerSecond: 3,
    });

    for (let i = 0; i < 8; i++) {
      writer.write(makeEvent(`evt-${i}`));
    }

    const metrics = writer.getMetrics();
    expect(metrics.totalEvents).toBe(8);
    expect(metrics.totalDropped).toBe(5);

    writer.close();
  });

  it('allows unlimited events when maxEventsPerSecond is 0', () => {
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
      bufferSize: 1000,
      flushIntervalMs: 60000,
      maxEventsPerSecond: 0,
    });

    for (let i = 0; i < 50; i++) {
      writer.write(makeEvent(`evt-${i}`));
    }
    writer.close();

    const content = fs.readFileSync(tracePath, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(50);
    expect(writer.getMetrics().totalDropped).toBe(0);
  });

  it('reports zero drops when under the limit', () => {
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
      bufferSize: 1000,
      flushIntervalMs: 60000,
      maxEventsPerSecond: 100,
    });

    for (let i = 0; i < 10; i++) {
      writer.write(makeEvent(`evt-${i}`));
    }

    const metrics = writer.getMetrics();
    expect(metrics.totalDropped).toBe(0);
    expect(metrics.totalEvents).toBe(10);

    writer.close();
  });
});
