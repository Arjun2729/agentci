import http from 'http';
import https from 'https';
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

function extractHost(options: any): { host: string; method: string } | null {
  if (!options) return null;
  if (typeof options === 'string') {
    try {
      const url = new URL(options);
      return { host: url.hostname, method: 'GET' };
    } catch {
      return null;
    }
  }
  if (options instanceof URL) {
    return { host: options.hostname, method: (options as any).method || 'GET' };
  }
  const host = options.hostname || options.host;
  if (!host) return null;
  const hostStr = String(host);
  // Guard against malicious objects with huge toString() or non-string types
  if (hostStr.length > 253) return null; // Max DNS hostname length
  return { host: hostStr.split(':')[0], method: String(options.method || 'GET') };
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
    logger.debug('http-patch', `Failed to record net_outbound for ${host}`, { error: String(err) });
  }
}

export function patchHttp(ctx: RecorderContext): void {
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;

  http.request = function (options: any, callback?: any) {
    if (!ctx.state.bypass) {
      const info = extractHost(options);
      if (info) recordNet(ctx, 'http', info.host, info.method);
    }
    return originalHttpRequest.call(http, options as any, callback as any);
  } as typeof http.request;

  https.request = function (options: any, callback?: any) {
    if (!ctx.state.bypass) {
      const info = extractHost(options);
      if (info) recordNet(ctx, 'https', info.host, info.method);
    }
    return originalHttpsRequest.call(https, options as any, callback as any);
  } as typeof https.request;
}
