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

function recordNet(
  ctx: RecorderContext,
  protocol: 'http' | 'https',
  host: string,
  method: string,
  port?: number
) {
  try {
    const data: EffectEventData = {
      category: 'net_outbound',
      kind: 'observed',
      net: {
        host_raw: host,
        host_etld_plus_1: toEtldPlus1(host),
        method,
        protocol,
        port
      }
    };
    ctx.writer.write(buildEvent(ctx, data));
    enforceEffect(ctx, data);
  } catch (err) {
    logger.debug('undici-patch', `Failed to record net_outbound for ${host}`, { error: String(err) });
  }
}

function extractFromUrl(input: any, method?: string): { host: string; protocol: 'http' | 'https'; port?: number; method: string } | null {
  try {
    if (typeof input === 'string') {
      const url = new URL(input);
      return {
        host: url.hostname,
        protocol: url.protocol === 'https:' ? 'https' : 'http',
        port: url.port ? Number(url.port) : undefined,
        method: method || 'GET'
      };
    }
    if (input instanceof URL) {
      return {
        host: input.hostname,
        protocol: input.protocol === 'https:' ? 'https' : 'http',
        port: input.port ? Number(input.port) : undefined,
        method: method || 'GET'
      };
    }
  } catch {
    return null;
  }
  return null;
}

export function patchUndici(ctx: RecorderContext): void {
  let undici: any;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    undici = require('undici');
  } catch {
    return;
  }
  if (!undici) return;

  if (typeof undici.request === 'function') {
    const originalRequest = undici.request.bind(undici);
    undici.request = function (url: any, opts?: any) {
      if (!ctx.state.bypass) {
        const info = extractFromUrl(url, opts?.method);
        if (info) {
          recordNet(ctx, info.protocol, info.host, info.method, info.port);
        }
      }
      return originalRequest(url, opts);
    };
  }

  if (typeof undici.fetch === 'function') {
    const originalFetch = undici.fetch.bind(undici);
    undici.fetch = function (input: any, init?: any) {
      if (!ctx.state.bypass) {
        const info = extractFromUrl(input, init?.method);
        if (info) {
          recordNet(ctx, info.protocol, info.host, info.method, info.port);
        }
      }
      return originalFetch(input, init);
    };
  }
}
