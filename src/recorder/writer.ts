import fs from 'fs';
import path from 'path';
import { TraceEvent } from '../core/types';
import { logger } from './logger';

export interface RecorderState {
  bypass: boolean;
}

export interface WriterOptions {
  runDir: string;
  tracePath: string;
  runId: string;
  originals: {
    appendFileSync: typeof fs.appendFileSync;
    mkdirSync: typeof fs.mkdirSync;
    writeFileSync: typeof fs.writeFileSync;
  };
  state: RecorderState;
  bufferSize?: number;
  flushIntervalMs?: number;
}

/**
 * Buffered trace writer. Collects events in memory and flushes to disk
 * when the buffer reaches `bufferSize` or every `flushIntervalMs`.
 *
 * This replaces the previous synchronous-per-event approach to reduce
 * I/O overhead on the monitored application.
 */
export class TraceWriter {
  private tracePath: string;
  private originals: WriterOptions['originals'];
  private state: RecorderState;
  private buffer: string[] = [];
  private bufferSize: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  constructor(options: WriterOptions) {
    this.tracePath = options.tracePath;
    this.originals = options.originals;
    this.state = options.state;
    this.bufferSize = options.bufferSize ?? 64;
    const flushInterval = options.flushIntervalMs ?? 250;

    try {
      this.originals.mkdirSync(path.dirname(this.tracePath), { recursive: true });
      if (!fs.existsSync(this.tracePath)) {
        this.originals.writeFileSync(this.tracePath, '', 'utf8');
      }
    } catch (err) {
      logger.error('writer', 'Failed to initialize trace file', { error: String(err) });
    }

    this.flushTimer = setInterval(() => this.flush(), flushInterval);
    if (this.flushTimer && typeof this.flushTimer === 'object' && 'unref' in this.flushTimer) {
      this.flushTimer.unref();
    }
  }

  write(event: TraceEvent): void {
    if (this.closed) return;
    try {
      const line = `${JSON.stringify(event)}\n`;
      this.buffer.push(line);
      if (this.buffer.length >= this.bufferSize) {
        this.flush();
      }
    } catch (err) {
      logger.error('writer', 'Failed to serialize event', { error: String(err) });
    }
  }

  flush(): void {
    if (!this.buffer.length) return;
    const data = this.buffer.join('');
    this.buffer = [];
    try {
      this.state.bypass = true;
      this.originals.appendFileSync(this.tracePath, data, 'utf8');
    } catch (err) {
      logger.error('writer', 'Failed to flush trace buffer', { error: String(err) });
    } finally {
      this.state.bypass = false;
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.flush();
  }
}
