import { randomUUID } from 'crypto';
import { RecorderContext } from '../context';
import { EffectEventData, TraceEvent } from '../../core/types';
import { toEtldPlus1 } from '../canonicalize';
import { logger } from '../logger';
import { enforceEffect } from '../enforce';

function now(): number {
  return Date.now();
}

function buildEvent(ctx: RecorderContext, data: EffectEventData): TraceEvent {
  return {
    id: randomUUID(),
    timestamp: now(),
    run_id: ctx.runId,
    type: 'effect',
    data
  };
}

function extractFetch(input: any, init?: any): { host: string; method: string; protocol: 'http' | 'https' } | null {
  try {
    if (typeof input === 'string') {
      const url = new URL(input);
      return {
        host: url.hostname,
        method: init?.method || 'GET',
        protocol: url.protocol === 'https:' ? 'https' : 'http'
      };
    }
    if (input instanceof URL) {
      return {
        host: input.hostname,
        method: init?.method || 'GET',
        protocol: input.protocol === 'https:' ? 'https' : 'http'
      };
    }
    if (input && typeof input === 'object' && 'url' in input) {
      const url = new URL((input as any).url);
      return {
        host: url.hostname,
        method: (input as any).method || init?.method || 'GET',
        protocol: url.protocol === 'https:' ? 'https' : 'http'
      };
    }
  } catch {
    return null;
  }
  return null;
}

function recordNet(ctx: RecorderContext, protocol: 'http' | 'https', host: string, method: string) {
  try {
    const data: EffectEventData = {
      category: 'net_outbound',
      kind: 'observed',
      net: {
        host_raw: host,
        host_etld_plus_1: toEtldPlus1(host),
        method,
        protocol
      }
    };
    ctx.writer.write(buildEvent(ctx, data));
    enforceEffect(ctx, data);
  } catch (err) {
    logger.debug('fetch-patch', `Failed to record net_outbound for ${host}`, { error: String(err) });
  }
}

export function patchFetch(ctx: RecorderContext): void {
  const originalFetch = globalThis.fetch;
  if (!originalFetch) return;

  globalThis.fetch = function (input: any, init?: any) {
    if (!ctx.state.bypass) {
      const info = extractFetch(input, init);
      if (info) recordNet(ctx, info.protocol, info.host, info.method);
    }
    return originalFetch(input as any, init as any);
  } as any;
}
