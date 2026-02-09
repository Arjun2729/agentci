/**
 * Tests for process crash and error recovery scenarios.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync } from 'child_process';

function createTempWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-crash-'));
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

describe('process crash and error recovery', () => {
  let workspace: string;

  beforeEach(() => {
    workspace = createTempWorkspace();
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
  });

  it('records error event on uncaught exception', () => {
    // The uncaughtException handler in register.ts catches the error and records
    // it. This prevents the default crash behavior, so exit code may be 0.
    // The important thing is the error event is recorded in the trace.
    const { events } = runAgentScript(
      workspace,
      `
      throw new Error('test crash');
    `,
    );

    const errorEvents = events.filter(
      (e) => e.type === 'lifecycle' && e.data.stage === 'error',
    );
    expect(errorEvents.length).toBeGreaterThanOrEqual(1);
    expect(errorEvents[0].metadata?.error).toContain('test crash');
  });

  it('flushes trace on non-zero exit', () => {
    const { exitCode, events } = runAgentScript(
      workspace,
      `
      const fs = require('fs');
      const path = require('path');
      fs.writeFileSync(path.join(process.cwd(), 'before-exit.txt'), 'data');
      process.exit(42);
    `,
    );

    expect(exitCode).toBe(42);
    const lifecycles = events.filter((e) => e.type === 'lifecycle');
    const stages = lifecycles.map((e) => e.data.stage);
    expect(stages).toContain('start');
    expect(stages).toContain('stop');

    // Verify the stop event has the exit code
    const stopEvent = lifecycles.find((e) => e.data.stage === 'stop');
    expect(stopEvent?.metadata?.exit_code).toBe(42);
  });

  it('records events even during rapid successive operations', () => {
    const { events } = runAgentScript(
      workspace,
      `
      const fs = require('fs');
      const path = require('path');
      // Rapidly write 50 files
      for (let i = 0; i < 50; i++) {
        fs.writeFileSync(path.join(process.cwd(), 'rapid_' + i + '.txt'), 'data');
      }
      process.exit(0);
    `,
    );

    const writes = events.filter((e) => e.type === 'effect' && e.data.category === 'fs_write');
    expect(writes.length).toBeGreaterThanOrEqual(50);
  });
});
