import path from 'path';
import picomatch from 'picomatch';

function normalizeGlob(input: string): string {
  if (input.startsWith('./')) return input.slice(2);
  return input;
}

export function normalizePathForMatch(p: string): string {
  const normalized = p.replace(/\\/g, '/');
  if (normalized.startsWith('./')) return normalized.slice(2);
  return normalized;
}

export function matchPath(globs: string[], candidate: string): boolean {
  if (!globs.length) return false;
  const normalizedCandidate = normalizePathForMatch(candidate);
  return globs.some((glob) => {
    const expanded = expandTilde(glob);
    const normalizedGlob = normalizeGlob(expanded.replace(/\\/g, '/'));
    const matcher = picomatch(normalizedGlob, { dot: true, nocase: false });
    return matcher(normalizedCandidate);
  });
}

export function expandTilde(p: string): string {
  if (p.startsWith('~/')) {
    const home = process.env.HOME || process.env.USERPROFILE || '';
    return path.join(home, p.slice(2));
  }
  return p;
}

export function matchHost(patterns: string[], host: string): boolean {
  if (!patterns.length) return false;
  const normalized = host.toLowerCase();
  return patterns.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern.startsWith('*.')) {
      const suffix = normalizedPattern.slice(1); // includes leading dot
      return normalized.endsWith(suffix);
    }
    return normalized === normalizedPattern;
  });
}
