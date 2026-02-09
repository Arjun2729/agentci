import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const API_KEY_PREFIX = 'agentci-';

export function generateApiKey(): string {
  return API_KEY_PREFIX + crypto.randomBytes(32).toString('hex');
}

export function hashApiKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

interface ApiKeyEntry {
  hash: string;
  team_id: string;
  name: string;
  created_at: string;
}

export function addApiKey(keysFile: string, key: string, teamId: string, name: string): void {
  let keys: ApiKeyEntry[] = [];
  try {
    keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
  } catch {
    // file doesn't exist or is invalid — start fresh
  }

  keys.push({
    hash: hashApiKey(key),
    team_id: teamId,
    name,
    created_at: new Date().toISOString(),
  });

  fs.mkdirSync(path.dirname(keysFile), { recursive: true });
  fs.writeFileSync(keysFile, JSON.stringify(keys, null, 2), { encoding: 'utf8', mode: 0o600 });
}

export function lookupApiKey(keysFile: string, key: string): ApiKeyEntry | null {
  let keys: ApiKeyEntry[] = [];
  try {
    keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
  } catch {
    return null;
  }

  const hash = hashApiKey(key);
  // Timing-safe comparison for each entry
  for (const entry of keys) {
    const entryBuf = Buffer.from(entry.hash, 'hex');
    const keyBuf = Buffer.from(hash, 'hex');
    if (entryBuf.length === keyBuf.length && crypto.timingSafeEqual(entryBuf, keyBuf)) {
      return entry;
    }
  }
  return null;
}
