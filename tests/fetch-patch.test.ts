/**
 * Integration tests for the fetch() patch.
 * Requires Node >= 18 for global fetch support.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';

function createTempWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-fetch-'));
  const runDir = path.join(dir, '.agentci', 'runs', 'test-run');
  fs.mkdirSync(runDir, { recursive: true });
  return dir;
}

function readTrace(workspace: string): any[] {
  const tracePath = path.join(workspace, '.agentci', 'runs', 'test-run', 'trace.jsonl');
  if (!fs.existsSync(tracePath)) return [];
  const content = fs.readFileSync(tracePath, 'utf8');
  return content
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function runAgentScript(workspace: string, scriptContent: string): { exitCode: number; events: any[] } {
  const scriptPath = path.join(workspace, '_test_agent.js');
  fs.writeFileSync(scriptPath, scriptContent, 'utf8');

  const registerPath = path.resolve(__dirname, '..', 'dist', 'recorder', 'register.js');
  const runDir = path.join(workspace, '.agentci', 'runs', 'test-run');

  const result = spawnSync('node', ['--require', registerPath, scriptPath], {
    cwd: workspace,
    env: {
      ...process.env,
      AGENTCI_RUN_DIR: runDir,
      AGENTCI_RUN_ID: 'test-run',
      AGENTCI_WORKSPACE_ROOT: workspace,
      AGENTCI_VERSION: '0.1.0',
    },
    timeout: 10000,
  });

  return {
    exitCode: result.status ?? 1,
    events: readTrace(workspace),
  };
}

describe('fetch() patch integration', () => {
  let workspace: string;

  beforeEach(() => {
    workspace = createTempWorkspace();
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
  });

  it('records net_outbound from fetch() with string URL', () => {
    const { events } = runAgentScript(
      workspace,
      `
      // Use fetch with a string URL — will fail but we only care about recording
      fetch('https://api.example.com/data').catch(() => {});
      setTimeout(() => process.exit(0), 500);
    `,
    );

    const netEvents = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'net_outbound',
    );
    expect(netEvents.length).toBeGreaterThanOrEqual(1);
    expect(netEvents[0].data.net.host_raw).toBe('api.example.com');
    expect(netEvents[0].data.net.protocol).toBe('https');
  });

  it('records correct HTTP method from fetch()', () => {
    const { events } = runAgentScript(
      workspace,
      `
      fetch('https://api.example.com/data', { method: 'POST' }).catch(() => {});
      setTimeout(() => process.exit(0), 500);
    `,
    );

    const netEvents = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'net_outbound',
    );
    expect(netEvents.length).toBeGreaterThanOrEqual(1);
    expect(netEvents[0].data.net.method).toBe('POST');
  });

  it('records fetch with URL object', () => {
    const { events } = runAgentScript(
      workspace,
      `
      const url = new URL('https://cdn.example.org/resource');
      fetch(url).catch(() => {});
      setTimeout(() => process.exit(0), 500);
    `,
    );

    const netEvents = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'net_outbound',
    );
    expect(netEvents.length).toBeGreaterThanOrEqual(1);
    expect(netEvents[0].data.net.host_raw).toBe('cdn.example.org');
  });
});
