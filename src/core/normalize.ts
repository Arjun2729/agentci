import crypto from 'crypto';
import path from 'path';
import { PolicyConfig } from './types';
import { matchHost, matchPath, normalizePathForMatch } from './policy/match';

const DEFAULT_MASK_PATTERNS = [
  'sk-[A-Za-z0-9]{10,}',
  'AKIA[0-9A-Z]{16}',
  'ASIA[0-9A-Z]{16}',
  'xox[baprs]-[A-Za-z0-9-]+',
  'ghp_[A-Za-z0-9]{20,}',
  'gho_[A-Za-z0-9]{20,}',
  'github_pat_[A-Za-z0-9_]{20,}',
  'hf_[A-Za-z0-9]{20,}',
  'eyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}', // JWT-ish
  '-----BEGIN [A-Z ]+-----',
];

const KEY_VALUE_HINT = /^(--?[^=]*?(token|key|secret|password)[^=]*)=/i;

const TEMP_PATTERNS = [
  /\/tmp\/[^/]+/gi,
  /\/var\/tmp\/[^/]+/gi,
  /\\Temp\\[^\\]+/gi,
  /\\tmp\\[^\\]+/gi,
  /\/private\/var\/folders\/[^/]+\/[^/]+\/[^/]+/gi,
];

function compilePatterns(patterns: string[]): RegExp[] {
  return patterns
    .map((pattern) => {
      try {
        return new RegExp(pattern, 'i');
      } catch {
        return null;
      }
    })
    .filter((value): value is RegExp => Boolean(value));
}

function collapseTemp(pathValue: string): string {
  let result = pathValue;
  for (const pattern of TEMP_PATTERNS) {
    result = result.replace(pattern, '/<temp>');
  }
  return result;
}

function collapseHome(pathValue: string): string {
  const home = process.env.HOME || process.env.USERPROFILE;
  if (!home) return pathValue;
  const normalizedHome = normalizePathForMatch(home.replace(/\\/g, '/'));
  const normalizedValue = normalizePathForMatch(pathValue);
  if (normalizedValue.startsWith(normalizedHome)) {
    return normalizedValue.replace(normalizedHome, '~');
  }
  return normalizedValue;
}

function hashValue(value: string): string {
  const hash = crypto.createHash('sha256').update(value).digest('hex');
  return `<hash:${hash}>`;
}

function applyRedaction(value: string, label: string, hashValues: boolean): string {
  if (hashValues) return hashValue(value);
  return `<redacted:${label}>`;
}

export function normalizeFsPath(value: string, config: PolicyConfig): string | null {
  if (!value) return null;
  const normalized = normalizePathForMatch(value.replace(/\\/g, '/'));
  const collapsedTemp = config.normalization.filesystem.collapse_temp ? collapseTemp(normalized) : normalized;
  const collapsedHome = config.normalization.filesystem.collapse_home ? collapseHome(collapsedTemp) : collapsedTemp;

  if (matchPath(config.normalization.filesystem.ignore_globs, collapsedHome)) {
    return null;
  }

  if (config.redaction.redact_paths.length && matchPath(config.redaction.redact_paths, collapsedHome)) {
    return applyRedaction(collapsedHome, 'path', config.redaction.hash_values);
  }

  return collapsedHome;
}

export function normalizeHost(host: string, config: PolicyConfig): string {
  if (!config.normalization.network.normalize_hosts) return host;
  let value = host.trim().toLowerCase();
  if (value.endsWith('.')) value = value.slice(0, -1);

  if (value.startsWith('[')) {
    const closing = value.indexOf(']');
    if (closing !== -1) {
      const rest = value.slice(closing + 1);
      if (rest.startsWith(':')) {
        return value.slice(0, closing + 1);
      }
      return value;
    }
  }

  if (/^[^:]+:\d+$/.test(value)) {
    value = value.split(':')[0];
  }

  if (config.redaction.redact_urls.length && matchHost(config.redaction.redact_urls, value)) {
    return applyRedaction(value, 'host', config.redaction.hash_values);
  }

  return value;
}

function maskArg(arg: string, patterns: RegExp[]): string {
  for (const pattern of patterns) {
    if (pattern.test(arg)) return '<redacted>';
  }
  const keyValueMatch = KEY_VALUE_HINT.exec(arg);
  if (keyValueMatch) {
    return `${keyValueMatch[1]}<redacted>`;
  }
  return arg;
}

export function normalizeExecCommand(command: string): string {
  if (!command) return command;
  return path.basename(command);
}

export function normalizeExecArgv(argv: string[], config: PolicyConfig): string[] {
  if (!argv.length) return argv;
  const patterns = compilePatterns([...DEFAULT_MASK_PATTERNS, ...(config.normalization.exec.mask_patterns || [])]);
  const masked = argv.map((arg) => maskArg(String(arg), patterns));
  const mode = config.normalization.exec.argv_mode;

  if (mode === 'none') {
    return [masked[0]];
  }
  if (mode === 'hash') {
    const hash = crypto.createHash('sha256').update(masked.join('\u0000')).digest('hex');
    return [masked[0], `<argv_hash:${hash}>`, `<argv_len:${masked.length}>`];
  }
  return masked;
}
