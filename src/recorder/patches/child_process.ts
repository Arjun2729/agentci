import childProcess from 'child_process';
import { randomUUID } from 'crypto';
import { RecorderContext } from '../context';
import { EffectEventData, TraceEvent } from '../../core/types';
import { normalizeCommand } from '../canonicalize';
import { logger } from '../logger';

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

function recordExec(ctx: RecorderContext, command: string, args: string[]): void {
  try {
    const normalized = normalizeCommand(command, args);
    const data: EffectEventData = {
      category: 'exec',
      kind: 'observed',
      exec: {
        command_raw: command,
        argv_normalized: normalized.argv
      }
    };
    ctx.writer.write(buildEvent(ctx, data));
  } catch (err) {
    logger.debug('exec-patch', `Failed to record exec for ${command}`, { error: String(err) });
  }
}

export function patchChildProcess(ctx: RecorderContext): void {
  const original = {
    spawn: childProcess.spawn,
    exec: childProcess.exec,
    execFile: childProcess.execFile,
    fork: childProcess.fork
  };

  childProcess.spawn = function (command: any, args?: any, options?: any) {
    if (!ctx.state.bypass) {
      try {
        const argv = Array.isArray(args) ? args : [];
        recordExec(ctx, String(command), argv.map((arg) => String(arg)));
      } catch (err) {
        logger.debug('exec-patch', `Failed to record spawn for ${command}`, { error: String(err) });
      }
    }
    return original.spawn(command, args as any, options as any);
  } as typeof childProcess.spawn;

  childProcess.exec = function (command: any, options?: any, callback?: any) {
    if (!ctx.state.bypass) {
      recordExec(ctx, String(command), []);
    }
    return original.exec(command, options as any, callback as any);
  } as typeof childProcess.exec;

  childProcess.execFile = function (file: any, args?: any, options?: any, callback?: any) {
    if (!ctx.state.bypass) {
      const argv = Array.isArray(args) ? args : [];
      recordExec(ctx, String(file), argv.map((arg) => String(arg)));
    }
    return original.execFile(file, args as any, options as any, callback as any);
  } as typeof childProcess.execFile;

  childProcess.fork = function (modulePath: any, args?: any, options?: any) {
    if (!ctx.state.bypass) {
      const argv = Array.isArray(args) ? args : [];
      recordExec(ctx, String(modulePath), argv.map((arg) => String(arg)));
    }
    return original.fork(modulePath, args as any, options as any);
  } as typeof childProcess.fork;
}
