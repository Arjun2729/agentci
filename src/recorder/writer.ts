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
  /** Maximum events per second before dropping. 0 = unlimited. Default: 10000 */
  maxEventsPerSecond?: number;
}

/**
 * Buffered trace writer. Collects events in memory and flushes to disk
 * when the buffer reaches `bufferSize` or every `flushIntervalMs`.
 *
 * Includes rate limiting to prevent event flooding from overwhelming
 * disk I/O or consuming excessive memory.
 */
export class TraceWriter {
  private tracePath: string;
  private originals: WriterOptions['originals'];
  private state: RecorderState;
  private buffer: string[] = [];
  private bufferSize: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  // Rate limiting
  private maxEventsPerSecond: number;
  private eventCountInWindow = 0;
  private windowStartMs = 0;
  private droppedInWindow = 0;
  private totalDropped = 0;
  private totalEvents = 0;

  constructor(options: WriterOptions) {
    this.tracePath = options.tracePath;
    this.originals = options.originals;
    this.state = options.state;
    this.bufferSize = options.bufferSize ?? 64;
    this.maxEventsPerSecond = options.maxEventsPerSecond ?? 10_000;
    const flushInterval = options.flushIntervalMs ?? 250;

    try {
      this.originals.mkdirSync(path.dirname(this.tracePath), { recursive: true });
      if (!fs.existsSync(this.tracePath)) {
        this.originals.writeFileSync(this.tracePath, '', { encoding: 'utf8', mode: 0o600 });
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

    this.totalEvents++;

    // Rate limiting: fixed window of 1 second
    if (this.maxEventsPerSecond > 0) {
      const now = Date.now();
      if (now - this.windowStartMs >= 1000) {
        // Window expired — log drops from previous window and reset
        if (this.droppedInWindow > 0) {
          logger.warn('writer', `Rate limit: dropped ${this.droppedInWindow} events in last window`);
        }
        this.windowStartMs = now;
        this.eventCountInWindow = 0;
        this.droppedInWindow = 0;
      }
      if (this.eventCountInWindow >= this.maxEventsPerSecond) {
        this.droppedInWindow++;
        this.totalDropped++;
        return;
      }
      this.eventCountInWindow++;
    }

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
    if (this.totalDropped > 0) {
      logger.warn('writer', `Rate limit: dropped ${this.totalDropped} events total during recording`);
    }
  }

  /** Returns writer metrics for observability. */
  getMetrics(): { totalEvents: number; totalDropped: number; bufferLength: number } {
    return {
      totalEvents: this.totalEvents,
      totalDropped: this.totalDropped,
      bufferLength: this.buffer.length,
    };
  }
}
