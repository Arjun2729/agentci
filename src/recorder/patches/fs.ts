import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { RecorderContext } from '../context';
import { EffectEventData, TraceEvent } from '../../core/types';
import { resolvePathBestEffort } from '../canonicalize';
import { expandTilde, matchPath } from '../../core/policy/match';
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

function pathFromArg(arg: unknown): string | null {
  if (typeof arg === 'string') return arg;
  if (Buffer.isBuffer(arg)) return arg.toString('utf8');
  if (arg instanceof URL) return arg.pathname;
  return null;
}

function shouldSkip(ctx: RecorderContext, resolvedPath: string): boolean {
  const agentciOriginal = path.resolve(ctx.workspaceRoot, '.agentci');
  if (resolvedPath.startsWith(agentciOriginal)) return true;
  // Also check realpath to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
  try {
    const agentciReal = fs.realpathSync.native(agentciOriginal);
    return resolvedPath.startsWith(agentciReal);
  } catch {
    return false;
  }
}

function recordFs(ctx: RecorderContext, category: EffectEventData['category'], inputPath: string): void {
  try {
    const resolved = resolvePathBestEffort(inputPath, ctx.workspaceRoot);
    if (shouldSkip(ctx, resolved.resolvedAbs)) return;
    const data: EffectEventData = {
      category,
      kind: 'observed',
      fs: {
        path_requested: inputPath,
        path_resolved: resolved.resolvedAbs,
        is_workspace_local: resolved.isWorkspaceLocal
      }
    };
    ctx.writer.write(buildEvent(ctx, data));

    if (category === 'fs_read') {
      const expanded = expandTilde(resolved.resolvedAbs);
      if (matchPath(ctx.config.policy.sensitive.block_file_globs, expanded)) {
        ctx.writer.write(
          buildEvent(ctx, {
            category: 'sensitive_access',
            kind: 'observed',
            sensitive: { type: 'file_read', key_name: expanded }
          })
        );
      }
    }
  } catch (err) {
    logger.debug('fs-patch', `Failed to record ${category} for ${inputPath}`, { error: String(err) });
  }
}

export function patchFs(ctx: RecorderContext): void {
  const original = {
    writeFile: fs.writeFile,
    writeFileSync: fs.writeFileSync,
    appendFile: fs.appendFile,
    appendFileSync: fs.appendFileSync,
    mkdir: fs.mkdir,
    mkdirSync: fs.mkdirSync,
    readFile: fs.readFile,
    readFileSync: fs.readFileSync,
    unlink: fs.unlink,
    unlinkSync: fs.unlinkSync,
    rm: fs.rm,
    rmSync: fs.rmSync,
    rename: fs.rename,
    renameSync: fs.renameSync
  };

  function wrapSync(
    fn: (...args: any[]) => any,
    category: EffectEventData['category'],
    pathIndex = 0
  ) {
    return function (...args: any[]) {
      if (ctx.state.bypass) return fn.apply(fs, args);
      const target = pathFromArg(args[pathIndex]);
      const result = fn.apply(fs, args);
      if (target) recordFs(ctx, category, target);
      return result;
    };
  }

  function wrapAsync(
    fn: (...args: any[]) => any,
    category: EffectEventData['category'],
    pathIndex = 0
  ) {
    return function (...args: any[]) {
      if (ctx.state.bypass) return fn.apply(fs, args);
      const target = pathFromArg(args[pathIndex]);
      const callback = args.find((arg) => typeof arg === 'function');
      if (callback) {
        const wrapped = function (err: Error | null, ...cbArgs: any[]) {
          if (!err && target) recordFs(ctx, category, target);
          return callback(err, ...cbArgs);
        };
        const newArgs = [...args];
        const cbIndex = newArgs.findIndex((arg) => typeof arg === 'function');
        newArgs[cbIndex] = wrapped;
        return fn.apply(fs, newArgs);
      }

      const result = fn.apply(fs, args);
      if (result && typeof result.then === 'function') {
        result.then(() => {
          if (target) recordFs(ctx, category, target);
        }).catch(() => {});
      } else if (target) {
        recordFs(ctx, category, target);
      }
      return result;
    };
  }

  fs.writeFile = wrapAsync(original.writeFile.bind(original), 'fs_write', 0);
  fs.writeFileSync = wrapSync(original.writeFileSync.bind(original), 'fs_write', 0);
  fs.appendFile = wrapAsync(original.appendFile.bind(original), 'fs_write', 0);
  fs.appendFileSync = wrapSync(original.appendFileSync.bind(original), 'fs_write', 0);
  fs.mkdir = wrapAsync(original.mkdir.bind(original), 'fs_write', 0);
  fs.mkdirSync = wrapSync(original.mkdirSync.bind(original), 'fs_write', 0);
  fs.readFile = wrapAsync(original.readFile.bind(original), 'fs_read', 0);
  fs.readFileSync = wrapSync(original.readFileSync.bind(original), 'fs_read', 0);
  fs.unlink = wrapAsync(original.unlink.bind(original), 'fs_delete', 0);
  fs.unlinkSync = wrapSync(original.unlinkSync.bind(original), 'fs_delete', 0);
  fs.rm = wrapAsync(original.rm.bind(original), 'fs_delete', 0);
  fs.rmSync = wrapSync(original.rmSync.bind(original), 'fs_delete', 0);

  fs.rename = function (oldPath: any, newPath: any, ...rest: any[]) {
    if (ctx.state.bypass) return original.rename(oldPath, newPath, ...rest);
    const oldTarget = pathFromArg(oldPath);
    const newTarget = pathFromArg(newPath);
    const callback = rest.find((arg) => typeof arg === 'function');
    if (callback) {
      const wrapped = function (err: Error | null, ...cbArgs: any[]) {
        if (!err) {
          if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
          if (newTarget) recordFs(ctx, 'fs_write', newTarget);
        }
        return callback(err, ...cbArgs);
      };
      const newArgs = [oldPath, newPath, ...rest];
      const cbIndex = newArgs.findIndex((arg) => typeof arg === 'function');
      newArgs[cbIndex] = wrapped;
      return original.rename.apply(fs, newArgs as any);
    }

    const result = original.rename(oldPath, newPath, ...rest);
    if (result && typeof result.then === 'function') {
      result.then(() => {
        if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
        if (newTarget) recordFs(ctx, 'fs_write', newTarget);
      }).catch(() => {});
    } else {
      if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
      if (newTarget) recordFs(ctx, 'fs_write', newTarget);
    }
    return result;
  } as typeof fs.rename;

  fs.renameSync = function (oldPath: any, newPath: any, ...rest: any[]) {
    if (ctx.state.bypass) return original.renameSync(oldPath, newPath, ...rest);
    const result = original.renameSync(oldPath, newPath, ...rest);
    const oldTarget = pathFromArg(oldPath);
    const newTarget = pathFromArg(newPath);
    if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
    if (newTarget) recordFs(ctx, 'fs_write', newTarget);
    return result;
  } as typeof fs.renameSync;
}
