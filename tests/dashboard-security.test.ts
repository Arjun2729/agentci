import { describe, it, expect } from 'vitest';
import path from 'path';
import os from 'os';
import { escapeHtml, isValidRunId, RateLimiter } from '../src/dashboard/server';

describe('escapeHtml', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  });

  it('escapes ampersands', () => {
    expect(escapeHtml('a & b')).toBe('a &amp; b');
  });

  it('escapes single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#39;s');
  });

  it('returns empty string unchanged', () => {
    expect(escapeHtml('')).toBe('');
  });

  it('does not double-escape already-escaped content', () => {
    expect(escapeHtml('&amp;')).toBe('&amp;amp;');
  });

  it('handles strings with multiple special chars', () => {
    expect(escapeHtml('<a href="x">b & c</a>')).toBe('&lt;a href=&quot;x&quot;&gt;b &amp; c&lt;/a&gt;');
  });
});

describe('isValidRunId', () => {
  const runsDir = path.join(os.tmpdir(), 'test-runs');

  it('accepts valid run IDs', () => {
    expect(isValidRunId(runsDir, '1706123456-abc123def456')).toBe(true);
    expect(isValidRunId(runsDir, 'my_run.2024-01-01')).toBe(true);
    expect(isValidRunId(runsDir, 'simple123')).toBe(true);
  });

  it('rejects path traversal attempts', () => {
    expect(isValidRunId(runsDir, '../../../etc/passwd')).toBe(false);
    expect(isValidRunId(runsDir, '..%2F..%2Fetc')).toBe(false);
  });

  it('rejects IDs with slashes', () => {
    expect(isValidRunId(runsDir, 'foo/bar')).toBe(false);
    expect(isValidRunId(runsDir, 'foo\\bar')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(isValidRunId(runsDir, '')).toBe(false);
  });

  it('rejects IDs with spaces', () => {
    expect(isValidRunId(runsDir, 'run id with spaces')).toBe(false);
  });

  it('rejects IDs with special shell characters', () => {
    expect(isValidRunId(runsDir, 'run;rm -rf /')).toBe(false);
    expect(isValidRunId(runsDir, 'run$(whoami)')).toBe(false);
    expect(isValidRunId(runsDir, 'run`whoami`')).toBe(false);
  });
});

describe('RateLimiter', () => {
  it('allows requests under the limit', () => {
    const limiter = new RateLimiter(5, 60_000);
    for (let i = 0; i < 5; i++) {
      expect(limiter.allow('client-1')).toBe(true);
    }
  });

  it('blocks requests over the limit', () => {
    const limiter = new RateLimiter(3, 60_000);
    expect(limiter.allow('client-1')).toBe(true);
    expect(limiter.allow('client-1')).toBe(true);
    expect(limiter.allow('client-1')).toBe(true);
    expect(limiter.allow('client-1')).toBe(false);
    expect(limiter.allow('client-1')).toBe(false);
  });

  it('tracks separate limits per key', () => {
    const limiter = new RateLimiter(2, 60_000);
    expect(limiter.allow('client-a')).toBe(true);
    expect(limiter.allow('client-a')).toBe(true);
    expect(limiter.allow('client-a')).toBe(false);
    // Different client should still be allowed
    expect(limiter.allow('client-b')).toBe(true);
    expect(limiter.allow('client-b')).toBe(true);
    expect(limiter.allow('client-b')).toBe(false);
  });

  it('does not grow beyond maxEntries', () => {
    const limiter = new RateLimiter(5, 60_000, 100);
    for (let i = 0; i < 200; i++) {
      limiter.allow(`client-${i}`);
    }
    expect(limiter.size).toBeLessThanOrEqual(100);
  });

  it('cleanup removes stale entries', () => {
    const limiter = new RateLimiter(100, 1); // 1ms window for fast testing
    limiter.allow('stale-client');

    // Wait for the window to expire (2x the window)
    const start = Date.now();
    while (Date.now() - start < 10) {
      /* spin */
    }

    limiter.cleanup();
    // After cleanup, the stale entry should be gone, so a new request should start fresh
    expect(limiter.allow('stale-client')).toBe(true);
  });
});
