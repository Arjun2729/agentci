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
  const candidates = [normalizedCandidate];
  const driveLetterRe = new RegExp('^[A-Za-z]:[\\\\/]');
  if (path.isAbsolute(candidate) || driveLetterRe.test(candidate)) {
    const stripped = normalizedCandidate.replace(new RegExp('^[A-Za-z]:/'), '').replace(/^\//, '');
    if (stripped && stripped !== normalizedCandidate) {
      candidates.push(stripped);
    }
  }
  return globs.some((glob) => {
    const expanded = expandTilde(glob);
    const normalizedGlob = normalizeGlob(expanded.replace(/\\/g, '/'));
    const matcher = picomatch(normalizedGlob, { dot: true, nocase: false });
    return candidates.some((value) => matcher(value));
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

export function matchKey(patterns: string[], value: string): boolean {
  if (!patterns.length) return false;
  return patterns.some((pattern) => {
    const matcher = picomatch(pattern, { dot: true, nocase: true });
    return matcher(value);
  });
}
