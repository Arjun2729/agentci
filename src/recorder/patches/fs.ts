import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { RecorderContext } from '../context';
import { EffectEventData, TraceEvent } from '../../core/types';
import { resolvePathBestEffort } from '../canonicalize';
import { expandTilde, matchPath } from '../../core/policy/match';
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

function pathFromArg(arg: unknown): string | null {
  if (typeof arg === 'string') return arg;
  if (Buffer.isBuffer(arg)) return arg.toString('utf8');
  if (arg instanceof URL) return arg.pathname;
  return null;
}

// Cache the .agentci realpath at patch-init time to avoid calling realpathSync on every hot-path.
let agentciOriginalCache: string | null = null;
let agentciRealCache: string | null = null;

function initAgentciPaths(workspaceRoot: string): void {
  agentciOriginalCache = path.resolve(workspaceRoot, '.agentci');
  try {
    agentciRealCache = fs.realpathSync.native(agentciOriginalCache);
  } catch {
    agentciRealCache = null;
  }
}

function shouldSkip(resolvedPath: string): boolean {
  if (agentciOriginalCache && resolvedPath.startsWith(agentciOriginalCache)) return true;
  if (agentciRealCache && resolvedPath.startsWith(agentciRealCache)) return true;
  return false;
}

function recordFs(ctx: RecorderContext, category: EffectEventData['category'], inputPath: string): void {
  try {
    const resolved = resolvePathBestEffort(inputPath, ctx.workspaceRoot);
    if (shouldSkip(resolved.resolvedAbs)) return;
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
    enforceEffect(ctx, data);

    if (category === 'fs_read') {
      const expanded = expandTilde(resolved.resolvedAbs);
      if (matchPath(ctx.config.policy.sensitive.block_file_globs, expanded)) {
        const sensitiveEvent: EffectEventData = {
          category: 'sensitive_access',
          kind: 'observed',
          sensitive: { type: 'file_read', key_name: expanded }
        };
        ctx.writer.write(buildEvent(ctx, sensitiveEvent));
        enforceEffect(ctx, sensitiveEvent);
      }
    }
  } catch (err) {
    logger.debug('fs-patch', `Failed to record ${category} for ${inputPath}`, { error: String(err) });
  }
}

export function patchFs(ctx: RecorderContext): void {
  initAgentciPaths(ctx.workspaceRoot);

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
    renameSync: fs.renameSync,
    promises: fs.promises ? { ...fs.promises } : null
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
        // Record only on success; re-throw errors without swallowing
        return result.then(
          (value: unknown) => {
            if (target) recordFs(ctx, category, target);
            return value;
          },
          (err: unknown) => {
            throw err;
          },
        );
      } else if (target) {
        recordFs(ctx, category, target);
      }
      return result;
    };
  }

  // Runtime monkey-patching requires casting through any
  const _fs = fs as any;
  _fs.writeFile = wrapAsync(original.writeFile.bind(original), 'fs_write', 0);
  _fs.writeFileSync = wrapSync(original.writeFileSync.bind(original), 'fs_write', 0);
  _fs.appendFile = wrapAsync(original.appendFile.bind(original), 'fs_write', 0);
  _fs.appendFileSync = wrapSync(original.appendFileSync.bind(original), 'fs_write', 0);
  _fs.mkdir = wrapAsync(original.mkdir.bind(original), 'fs_write', 0);
  _fs.mkdirSync = wrapSync(original.mkdirSync.bind(original), 'fs_write', 0);
  _fs.readFile = wrapAsync(original.readFile.bind(original), 'fs_read', 0);
  _fs.readFileSync = wrapSync(original.readFileSync.bind(original), 'fs_read', 0);
  _fs.unlink = wrapAsync(original.unlink.bind(original), 'fs_delete', 0);
  _fs.unlinkSync = wrapSync(original.unlinkSync.bind(original), 'fs_delete', 0);
  _fs.rm = wrapAsync(original.rm.bind(original), 'fs_delete', 0);
  _fs.rmSync = wrapSync(original.rmSync.bind(original), 'fs_delete', 0);

  _fs.rename = function (oldPath: any, newPath: any, ...rest: any[]) {
    if (ctx.state.bypass) return (original.rename as any).call(fs, oldPath, newPath, ...rest);
    const oldTarget = pathFromArg(oldPath);
    const newTarget = pathFromArg(newPath);
    const callback = rest.find((arg: any) => typeof arg === 'function');
    if (callback) {
      const wrapped = function (err: Error | null, ...cbArgs: any[]) {
        if (!err) {
          if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
          if (newTarget) recordFs(ctx, 'fs_write', newTarget);
        }
        return callback(err, ...cbArgs);
      };
      const newArgs = [oldPath, newPath, ...rest];
      const cbIndex = newArgs.findIndex((arg: any) => typeof arg === 'function');
      newArgs[cbIndex] = wrapped;
      return original.rename.apply(fs, newArgs as any);
    }

    const result = (original.rename as any).call(fs, oldPath, newPath, ...rest);
    if (result && typeof result.then === 'function') {
      return result.then(
        (value: unknown) => {
          if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
          if (newTarget) recordFs(ctx, 'fs_write', newTarget);
          return value;
        },
        (err: unknown) => {
          throw err;
        },
      );
    } else {
      if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
      if (newTarget) recordFs(ctx, 'fs_write', newTarget);
    }
    return result;
  };

  _fs.renameSync = function (oldPath: any, newPath: any, ...rest: any[]) {
    if (ctx.state.bypass) return (original.renameSync as any).call(fs, oldPath, newPath, ...rest);
    const result = (original.renameSync as any).call(fs, oldPath, newPath, ...rest);
    const oldTarget = pathFromArg(oldPath);
    const newTarget = pathFromArg(newPath);
    if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
    if (newTarget) recordFs(ctx, 'fs_write', newTarget);
    return result;
  };

  if (original.promises) {
    const p = original.promises as typeof fs.promises;
    const wrapPromise = (
      fn: (...args: any[]) => Promise<any>,
      category: EffectEventData['category'],
      pathIndex = 0
    ) => {
      return async function (...args: any[]) {
        if (ctx.state.bypass) return fn.apply(p, args as any);
        const target = pathFromArg(args[pathIndex]);
        const result = await fn.apply(p, args as any);
        if (target) recordFs(ctx, category, target);
        return result;
      };
    };

    fs.promises.writeFile = wrapPromise(p.writeFile.bind(p), 'fs_write', 0) as any;
    fs.promises.appendFile = wrapPromise(p.appendFile.bind(p), 'fs_write', 0) as any;
    fs.promises.mkdir = wrapPromise(p.mkdir.bind(p), 'fs_write', 0) as any;
    fs.promises.readFile = wrapPromise(p.readFile.bind(p), 'fs_read', 0) as any;
    fs.promises.unlink = wrapPromise(p.unlink.bind(p), 'fs_delete', 0) as any;
    fs.promises.rm = wrapPromise(p.rm.bind(p), 'fs_delete', 0) as any;
    fs.promises.rename = async function (oldPath: any, newPath: any, ...rest: any[]) {
      if (ctx.state.bypass) return (p.rename as any).call(p, oldPath, newPath, ...rest);
      const result = await (p.rename as any).call(p, oldPath, newPath, ...rest);
      const oldTarget = pathFromArg(oldPath);
      const newTarget = pathFromArg(newPath);
      if (oldTarget) recordFs(ctx, 'fs_delete', oldTarget);
      if (newTarget) recordFs(ctx, 'fs_write', newTarget);
      return result;
    } as any;
  }
}
