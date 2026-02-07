import fs from 'fs';
import path from 'path';
import psl from 'psl';

export function toEtldPlus1(host: string): string {
  const trimmed = host.trim().toLowerCase();
  const parsed = psl.parse(trimmed);
  if (typeof parsed === 'object' && 'domain' in parsed && parsed.domain) {
    return parsed.domain;
  }
  return trimmed;
}

export function resolvePathBestEffort(inputPath: string, workspaceRoot: string): {
  requestedAbs: string;
  resolvedAbs: string;
  isWorkspaceLocal: boolean;
  isSymlinkEscape: boolean;
} {
  const workspaceResolved = safeRealpath(workspaceRoot) || path.resolve(workspaceRoot);
  const workspaceOriginal = path.resolve(workspaceRoot);
  const requestedAbs = path.resolve(process.cwd(), inputPath);
  const resolvedAbs = safeRealpath(requestedAbs) || requestedAbs;
  const requestedInside =
    isSubpath(requestedAbs, workspaceResolved) || isSubpath(requestedAbs, workspaceOriginal);
  const resolvedInside =
    isSubpath(resolvedAbs, workspaceResolved) || isSubpath(resolvedAbs, workspaceOriginal);
  const isSymlinkEscape = requestedInside && !resolvedInside;
  return {
    requestedAbs,
    resolvedAbs,
    isWorkspaceLocal: resolvedInside || requestedInside,
    isSymlinkEscape
  };
}

export function toWorkspacePath(resolvedAbs: string, workspaceRoot: string): { value: string; isExternal: boolean } {
  const workspaceResolved = safeRealpath(workspaceRoot) || path.resolve(workspaceRoot);
  const workspaceOriginal = path.resolve(workspaceRoot);
  if (isSubpath(resolvedAbs, workspaceResolved)) {
    return { value: path.relative(workspaceResolved, resolvedAbs), isExternal: false };
  }
  if (isSubpath(resolvedAbs, workspaceOriginal)) {
    return { value: path.relative(workspaceOriginal, resolvedAbs), isExternal: false };
  }
  return { value: resolvedAbs, isExternal: true };
}

export function normalizeCommand(command: string, args: string[]): { command: string; argv: string[] } {
  const base = path.basename(command);
  const normalizedArgs = args.map((arg) => normalizeArg(arg));
  return { command: base || command, argv: [base || command, ...normalizedArgs] };
}

function normalizeArg(arg: string): string {
  if (!arg) return arg;
  const tmpPatterns = [/\/tmp\//, /\\Temp\\/i, /\\tmp\\/i];
  const isTemp = tmpPatterns.some((re) => re.test(arg));
  if (isTemp) return '<temp>'; // strip obvious temp noise
  return arg;
}

function safeRealpath(p: string): string | null {
  try {
    return fs.realpathSync.native(p);
  } catch (err) {
    try {
      return fs.realpathSync(p);
    } catch (err2) {
      return null;
    }
  }
}

function isSubpath(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  if (!relative) return true;
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}
