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
    data,
  };
}

function splitHostPort(value: string): { host: string; port?: number } {
  if (value.startsWith('[')) {
    const closing = value.indexOf(']');
    if (closing !== -1) {
      const host = value.slice(0, closing + 1);
      const rest = value.slice(closing + 1);
      if (rest.startsWith(':')) {
        const port = Number(rest.slice(1));
        return Number.isFinite(port) ? { host, port } : { host };
      }
      return { host };
    }
  }
  const parts = value.split(':');
  if (parts.length === 2) {
    const port = Number(parts[1]);
    if (Number.isFinite(port)) {
      return { host: parts[0], port };
    }
  }
  return { host: value };
}

function extractHost(options: any): { host: string; method: string; port?: number } | null {
  if (!options) return null;
  if (typeof options === 'string') {
    try {
      const url = new URL(options);
      const port = url.port ? Number(url.port) : undefined;
      return { host: url.hostname, method: 'GET', port };
    } catch {
      return null;
    }
  }
  if (options instanceof URL) {
    const port = options.port ? Number(options.port) : undefined;
    return { host: options.hostname, method: (options as any).method || 'GET', port };
  }
  const host = options.hostname || options.host;
  if (!host) return null;
  const hostStr = String(host);
  // Guard against malicious objects with huge toString() or non-string types
  if (hostStr.length > 253) return null; // Max DNS hostname length
  const parsed = splitHostPort(hostStr);
  const port = options.port ? Number(options.port) : parsed.port;
  return { host: parsed.host, method: String(options.method || 'GET'), port: Number.isFinite(port) ? port : undefined };
}

function recordNet(ctx: RecorderContext, protocol: 'http' | 'https', host: string, method: string, port?: number) {
  try {
    const data: EffectEventData = {
      category: 'net_outbound',
      kind: 'observed',
      net: {
        host_raw: host,
        host_etld_plus_1: toEtldPlus1(host),
        method,
        protocol,
        port,
      },
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
      if (info) recordNet(ctx, 'http', info.host, info.method, info.port);
    }
    return originalHttpRequest.call(http, options as any, callback as any);
  } as typeof http.request;

  https.request = function (options: any, callback?: any) {
    if (!ctx.state.bypass) {
      const info = extractHost(options);
      if (info) recordNet(ctx, 'https', info.host, info.method, info.port);
    }
    return originalHttpsRequest.call(https, options as any, callback as any);
  } as typeof https.request;
}
