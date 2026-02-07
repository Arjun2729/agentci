import { describe, it, expect } from 'vitest';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { toEtldPlus1, resolvePathBestEffort, toWorkspacePath } from '../src/recorder/canonicalize';

describe('canonicalize', () => {
  it('computes eTLD+1', () => {
    expect(toEtldPlus1('api.weather.com')).toBe('weather.com');
    expect(toEtldPlus1('localhost')).toBe('localhost');
  });

  it('resolves workspace paths and detects external', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-'));
    const inside = path.join(root, 'file.txt');
    const res = resolvePathBestEffort(inside, root);
    expect(res.isWorkspaceLocal).toBe(true);
    const workspacePath = toWorkspacePath(res.resolvedAbs, root);
    expect(workspacePath.isExternal).toBe(false);
  });
});
