import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fc from 'fast-check';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { summarizeTrace } from '../src/core/signature/summarize.js';
import { diffSignatures } from '../src/core/diff/diff.js';
import { readJsonl } from '../src/core/trace/read_jsonl.js';
import { computeTraceHmac } from '../src/core/integrity.js';
import { normalizeFsPath } from '../src/core/normalize.js';
import { arbitraryTraceEvent, defaultConfig } from './helpers/arbitraries.js';
import type { TraceEvent } from '../src/core/types.js';

describe('property-based tests', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-prop-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeTrace(events: TraceEvent[]): string {
    const tracePath = path.join(tmpDir, 'trace.jsonl');
    const content = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
    fs.writeFileSync(tracePath, content);
    return tracePath;
  }

  it('signature generation is deterministic', () => {
    fc.assert(
      fc.property(fc.array(arbitraryTraceEvent('prop-run'), { minLength: 1, maxLength: 20 }), (events) => {
        const tracePath = writeTrace(events);
        const config = defaultConfig();
        const sig1 = summarizeTrace(tracePath, config, '0.1.0');
        const sig2 = summarizeTrace(tracePath, config, '0.1.0');
        expect(sig1.effects).toEqual(sig2.effects);
      }),
      { numRuns: 50 },
    );
  });

  it('diff of identical signatures produces empty drift', () => {
    fc.assert(
      fc.property(fc.array(arbitraryTraceEvent('diff-run'), { minLength: 1, maxLength: 15 }), (events) => {
        const tracePath = writeTrace(events);
        const config = defaultConfig();
        const sig = summarizeTrace(tracePath, config, '0.1.0');
        const result = diffSignatures(sig, sig);

        // All drift arrays should be empty
        for (const key of Object.keys(result.drift) as (keyof typeof result.drift)[]) {
          expect(result.drift[key]).toEqual([]);
        }
      }),
      { numRuns: 50 },
    );
  });

  it('normalization is idempotent', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant('./src/index.ts'),
          fc.constant('/etc/hosts'),
          fc.constant('/tmp/random-dir/file.txt'),
          fc.constant('~/documents/notes.md'),
          fc.constant('./workspace/deep/nested/path/file.js'),
        ),
        (p) => {
          const config = defaultConfig();
          const first = normalizeFsPath(p, config);
          if (first === null) return; // filtered by ignore_globs
          const second = normalizeFsPath(first, config);
          expect(second).toBe(first);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('HMAC produces different outputs for different inputs', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.string({ minLength: 1, maxLength: 200 }),
        (content1, content2) => {
          fc.pre(content1 !== content2);

          const trace1 = path.join(tmpDir, 'a.jsonl');
          const trace2 = path.join(tmpDir, 'b.jsonl');
          fs.writeFileSync(trace1, content1);
          fs.writeFileSync(trace2, content2);

          const secret = crypto.randomBytes(32).toString('hex');
          const hmac1 = computeTraceHmac(trace1, 'run1', secret);
          const hmac2 = computeTraceHmac(trace2, 'run1', secret);

          expect(hmac1).not.toBe(hmac2);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('JSONL parser never throws on arbitrary input', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 500 }), (content) => {
        const tracePath = path.join(tmpDir, 'fuzz.jsonl');
        fs.writeFileSync(tracePath, content);

        // Should never throw
        const result = readJsonl(tracePath);
        expect(Array.isArray(result)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('adding events never reduces signature set sizes', () => {
    fc.assert(
      fc.property(
        fc.array(arbitraryTraceEvent('mono-run'), { minLength: 1, maxLength: 10 }),
        fc.array(arbitraryTraceEvent('mono-run'), { minLength: 1, maxLength: 10 }),
        (events1, events2) => {
          const config = defaultConfig();

          const trace1 = writeTrace(events1);
          const sig1 = summarizeTrace(trace1, config, '0.1.0');

          // Combined events should have >= the same number of unique effects
          const combined = [...events1, ...events2];
          const trace2 = writeTrace(combined);
          const sig2 = summarizeTrace(trace2, config, '0.1.0');

          // Each effect category in sig2 should be >= sig1
          for (const key of Object.keys(sig1.effects) as (keyof typeof sig1.effects)[]) {
            const set1 = new Set(sig1.effects[key].map(String));
            const set2 = new Set(sig2.effects[key].map(String));
            for (const item of set1) {
              expect(set2.has(item)).toBe(true);
            }
          }
        },
      ),
      { numRuns: 30 },
    );
  });

  it('signature effect arrays are always sorted', () => {
    fc.assert(
      fc.property(fc.array(arbitraryTraceEvent('sort-run'), { minLength: 1, maxLength: 20 }), (events) => {
        const tracePath = writeTrace(events);
        const config = defaultConfig();
        const sig = summarizeTrace(tracePath, config, '0.1.0');

        for (const key of Object.keys(sig.effects) as (keyof typeof sig.effects)[]) {
          const arr = sig.effects[key];
          if (key === 'net_ports') {
            const nums = arr as number[];
            for (let i = 1; i < nums.length; i++) {
              expect(nums[i]).toBeGreaterThanOrEqual(nums[i - 1]);
            }
          } else {
            const strs = arr as string[];
            for (let i = 1; i < strs.length; i++) {
              expect(strs[i] >= strs[i - 1]).toBe(true);
            }
          }
        }
      }),
      { numRuns: 50 },
    );
  });
});
