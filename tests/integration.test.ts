/**
 * Integration tests for the AgentCI recording pipeline.
 *
 * These tests exercise the full chain: patches -> writer -> trace.jsonl
 * by invoking the recorder in a controlled subprocess.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync, spawnSync } from 'child_process';

function createTempWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-integration-'));
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

describe('recording pipeline integration', () => {
  let workspace: string;

  beforeEach(() => {
    workspace = createTempWorkspace();
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
  });

  it('records lifecycle start and stop events', () => {
    const { events } = runAgentScript(workspace, `
      // minimal agent that does nothing
      process.exit(0);
    `);

    const lifecycles = events.filter((e) => e.type === 'lifecycle');
    const stages = lifecycles.map((e) => e.data.stage);
    expect(stages).toContain('start');
    expect(stages).toContain('stop');
  });

  it('records fs_write effects', () => {
    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      const path = require('path');
      const dir = path.join(process.cwd(), 'output');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'test.txt'), 'hello', 'utf8');
    `);

    const fsWrites = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'fs_write'
    );
    expect(fsWrites.length).toBeGreaterThanOrEqual(1);
    const writePaths = fsWrites.map((e) => e.data.fs?.path_requested || '');
    expect(writePaths.some((p) => p.includes('test.txt'))).toBe(true);
  });

  it('records fs_read effects', () => {
    // Create a file to read
    const testFile = path.join(workspace, 'data.txt');
    fs.writeFileSync(testFile, 'some data', 'utf8');

    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      const path = require('path');
      fs.readFileSync(path.join(process.cwd(), 'data.txt'), 'utf8');
    `);

    const fsReads = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'fs_read'
    );
    expect(fsReads.length).toBeGreaterThanOrEqual(1);
  });

  it('records fs_delete effects', () => {
    const testFile = path.join(workspace, 'to-delete.txt');
    fs.writeFileSync(testFile, 'delete me', 'utf8');

    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      const path = require('path');
      fs.unlinkSync(path.join(process.cwd(), 'to-delete.txt'));
    `);

    const fsDeletes = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'fs_delete'
    );
    expect(fsDeletes.length).toBeGreaterThanOrEqual(1);
  });

  it('records exec effects from child_process.spawn', () => {
    const { events } = runAgentScript(workspace, `
      const { spawn } = require('child_process');
      const child = spawn('echo', ['hello']);
      child.on('close', () => process.exit(0));
      setTimeout(() => process.exit(0), 2000);
    `);

    const execs = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'exec'
    );
    expect(execs.length).toBeGreaterThanOrEqual(1);
    expect(execs[0].data.exec.command_raw).toBe('echo');
  });

  it('records exec effects from child_process.exec', () => {
    const { events } = runAgentScript(workspace, `
      const { exec } = require('child_process');
      exec('echo hello', () => process.exit(0));
      setTimeout(() => process.exit(0), 2000);
    `);

    const execs = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'exec'
    );
    expect(execs.length).toBeGreaterThanOrEqual(1);
  });

  it('records net_outbound effects from http', () => {
    const { events } = runAgentScript(workspace, `
      const http = require('http');
      const req = http.request({ hostname: 'localhost', port: 1, method: 'GET', timeout: 100 });
      req.on('error', () => {});
      req.end();
      setTimeout(() => process.exit(0), 200);
    `);

    const netEvents = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'net_outbound'
    );
    expect(netEvents.length).toBeGreaterThanOrEqual(1);
    expect(netEvents[0].data.net.host_raw).toBe('localhost');
    expect(netEvents[0].data.net.protocol).toBe('http');
  });

  it('buffers events and flushes on process exit', () => {
    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      const path = require('path');
      // Write multiple files rapidly
      for (let i = 0; i < 10; i++) {
        fs.writeFileSync(path.join(process.cwd(), 'file_' + i + '.txt'), 'data ' + i);
      }
    `);

    const fsWrites = events.filter(
      (e) => e.type === 'effect' && e.data.category === 'fs_write'
    );
    // Should have recorded all writes (buffered and flushed on exit)
    expect(fsWrites.length).toBeGreaterThanOrEqual(10);
  });

  it('does not record its own trace writes', () => {
    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      fs.writeFileSync(require('path').join(process.cwd(), 'output.txt'), 'hello');
    `);

    const traceWrites = events.filter(
      (e) =>
        e.type === 'effect' &&
        e.data.category === 'fs_write' &&
        e.data.fs?.path_requested?.includes('trace.jsonl')
    );
    expect(traceWrites.length).toBe(0);
  });

  it('does not record writes to .agentci directory', () => {
    const { events } = runAgentScript(workspace, `
      const fs = require('fs');
      const path = require('path');
      const agentciDir = path.join(process.cwd(), '.agentci', 'temp');
      fs.mkdirSync(agentciDir, { recursive: true });
      fs.writeFileSync(path.join(agentciDir, 'internal.txt'), 'internal');
    `);

    const agentciWrites = events.filter(
      (e) =>
        e.type === 'effect' &&
        e.data.category === 'fs_write' &&
        e.data.fs?.path_resolved?.includes('.agentci')
    );
    expect(agentciWrites.length).toBe(0);
  });
});
