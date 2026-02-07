import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { TraceWriter } from './writer';
import { RecorderContext } from './context';
import { patchFs } from './patches/fs';
import { patchChildProcess } from './patches/child_process';
import { patchHttp } from './patches/http';
import { patchFetch } from './patches/fetch';
import { loadConfig } from '../core/policy/config';
import { TraceEvent } from '../core/types';
import { logger } from './logger';

function now(): number {
  return Date.now();
}

function buildLifecycle(ctx: RecorderContext, stage: 'start' | 'stop' | 'error', metadata?: Record<string, unknown>): TraceEvent {
  return {
    id: randomUUID(),
    timestamp: now(),
    run_id: ctx.runId,
    type: 'lifecycle',
    data: { stage },
    metadata
  };
}

function patchEnvSensitive(ctx: RecorderContext): void {
  const blocked = new Set(ctx.config.policy.sensitive.block_env);
  if (!blocked.size) return;
  const originalEnv = process.env;
  process.env = new Proxy(originalEnv, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && blocked.has(prop)) {
        ctx.writer.write({
          id: randomUUID(),
          timestamp: now(),
          run_id: ctx.runId,
          type: 'effect',
          data: {
            category: 'sensitive_access',
            kind: 'observed',
            sensitive: { type: 'env_var', key_name: prop }
          }
        });
      }
      return Reflect.get(target, prop, receiver);
    }
  });
}

function initRecorder(): void {
  const runDir = process.env.AGENTCI_RUN_DIR;
  if (!runDir) return;

  logger.debug('register', 'Initializing recorder', { runDir });

  const workspaceRoot = process.env.AGENTCI_WORKSPACE_ROOT || process.cwd();
  const configPath = process.env.AGENTCI_CONFIG_PATH;
  const config = loadConfig(configPath, workspaceRoot);

  const runId = process.env.AGENTCI_RUN_ID || path.basename(runDir);
  const tracePath = path.join(runDir, 'trace.jsonl');

  const state = { bypass: false };
  const writer = new TraceWriter({
    runDir,
    tracePath,
    runId,
    originals: {
      appendFileSync: fs.appendFileSync,
      mkdirSync: fs.mkdirSync,
      writeFileSync: fs.writeFileSync
    },
    state
  });

  const ctx: RecorderContext = {
    runId,
    runDir,
    workspaceRoot,
    config,
    writer,
    state,
    originals: {
      fs,
      appendFileSync: fs.appendFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync
    }
  };

  const startedAt = now();
  writer.write(
    buildLifecycle(ctx, 'start', {
      node_version: process.version,
      platform: `${process.platform}-${process.arch}`
    })
  );

  try {
    patchEnvSensitive(ctx);
    logger.debug('register', 'Patched env sensitive');
    patchFs(ctx);
    logger.debug('register', 'Patched fs');
    patchChildProcess(ctx);
    logger.debug('register', 'Patched child_process');
    patchHttp(ctx);
    logger.debug('register', 'Patched http/https');
    patchFetch(ctx);
    logger.debug('register', 'Patched fetch');
  } catch (err) {
    logger.error('register', 'Failed to apply patches', { error: String(err) });
    writer.write(buildLifecycle(ctx, 'error', { error: String(err) }));
  }

  let stopped = false;
  const stopOnce = (metadata?: Record<string, unknown>) => {
    if (stopped) return;
    stopped = true;
    const duration = now() - startedAt;
    writer.write(buildLifecycle(ctx, 'stop', { duration_ms: duration, ...metadata }));
    writer.close();
  };

  process.on('exit', (code) => stopOnce({ exit_code: code }));
  process.on('uncaughtException', (err) => {
    logger.error('register', 'Uncaught exception', { error: String(err) });
    writer.write(buildLifecycle(ctx, 'error', { error: String(err) }));
    stopOnce({ exit_code: 1 });
  });
  process.on('unhandledRejection', (reason) => {
    logger.error('register', 'Unhandled rejection', { error: String(reason) });
    writer.write(buildLifecycle(ctx, 'error', { error: String(reason) }));
    stopOnce({ exit_code: 1 });
  });
}

initRecorder();
