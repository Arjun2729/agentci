import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { resolvePathBestEffort } from '../src/recorder/canonicalize';

describe('symlink attack detection', () => {
  let tmpDir: string;
  let workspaceDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-symlink-'));
    workspaceDir = path.join(tmpDir, 'workspace');
    fs.mkdirSync(workspaceDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('detects symlink pointing outside workspace', () => {
    // Create a directory outside workspace
    const outsideDir = path.join(tmpDir, 'outside');
    fs.mkdirSync(outsideDir, { recursive: true });
    fs.writeFileSync(path.join(outsideDir, 'secret.txt'), 'secret-data', 'utf8');

    // Create symlink inside workspace pointing outside
    const symlinkPath = path.join(workspaceDir, 'evil-link');
    fs.symlinkSync(outsideDir, symlinkPath);

    const result = resolvePathBestEffort(path.join(workspaceDir, 'evil-link', 'secret.txt'), workspaceDir);
    expect(result.isSymlinkEscape).toBe(true);
  });

  it('does not flag normal symlinks within workspace', () => {
    const subDir = path.join(workspaceDir, 'src');
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, 'index.ts'), 'export {}', 'utf8');

    // Symlink within workspace
    const linkPath = path.join(workspaceDir, 'link-to-src');
    fs.symlinkSync(subDir, linkPath);

    const result = resolvePathBestEffort(path.join(workspaceDir, 'link-to-src', 'index.ts'), workspaceDir);
    expect(result.isSymlinkEscape).toBe(false);
    expect(result.isWorkspaceLocal).toBe(true);
  });

  it('handles non-existent symlink targets gracefully', () => {
    const brokenLink = path.join(workspaceDir, 'broken');
    fs.symlinkSync('/nonexistent/path/that/does/not/exist', brokenLink);

    const result = resolvePathBestEffort(brokenLink, workspaceDir);
    // Should not crash, should report as workspace local (requested path is inside)
    expect(result.requestedAbs).toContain('broken');
  });

  it('detects parent directory escape via ..', () => {
    const result = resolvePathBestEffort(path.join(workspaceDir, '..', '..', 'etc', 'passwd'), workspaceDir);
    expect(result.isWorkspaceLocal).toBe(false);
  });

  it('correctly resolves workspace-local paths', () => {
    const filePath = path.join(workspaceDir, 'src', 'app.ts');
    fs.mkdirSync(path.join(workspaceDir, 'src'), { recursive: true });
    fs.writeFileSync(filePath, 'export {}', 'utf8');

    const result = resolvePathBestEffort(filePath, workspaceDir);
    expect(result.isWorkspaceLocal).toBe(true);
    expect(result.isSymlinkEscape).toBe(false);
  });
});
