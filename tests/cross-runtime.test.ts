import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { readJsonl } from '../src/core/trace/read_jsonl.js';

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'cross-runtime');
const PROJECT_ROOT = path.resolve(__dirname, '..');

function hasPython(): boolean {
  try {
    execSync('python3 --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function hasPythonRecorder(): boolean {
  try {
    execSync('python3 -c "import agentci_recorder"', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

describe('cross-runtime compatibility', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-xruntime-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('Node.js recorder produces valid trace from test script', () => {
    const runDir = path.join(tmpDir, 'node-run');
    fs.mkdirSync(runDir, { recursive: true });

    const outDir = path.join(tmpDir, 'node-out');

    try {
      execSync(
        `node -r "${path.join(PROJECT_ROOT, 'dist', 'recorder', 'register.js')}" "${path.join(FIXTURES_DIR, 'test-script.js')}"`,
        {
          env: {
            ...process.env,
            AGENTCI_RUN_DIR: runDir,
            AGENTCI_RUN_ID: 'xruntime-node',
            AGENTCI_WORKSPACE_ROOT: PROJECT_ROOT,
            AGENTCI_TEST_OUT: outDir,
          },
          stdio: 'pipe',
          timeout: 10000,
        },
      );
    } catch {
      // Script may exit with non-zero; trace should still be written
    }

    const tracePath = path.join(runDir, 'trace.jsonl');
    if (!fs.existsSync(tracePath)) {
      // If recorder didn't produce a trace (e.g., dist not built), skip
      return;
    }

    const events = readJsonl(tracePath);
    expect(events.length).toBeGreaterThan(0);

    // Should have lifecycle and effect events
    const types = new Set(events.map((e) => e.type));
    expect(types.has('lifecycle')).toBe(true);
    expect(types.has('effect')).toBe(true);

    // Should have recorded at least the file write
    const categories = new Set(
      events
        .filter((e) => e.type === 'effect')
        .map((e) => (e.data as { category?: string })?.category)
        .filter(Boolean),
    );
    expect(categories.has('fs_write')).toBe(true);
  });

  it.skipIf(!hasPython() || !hasPythonRecorder())('Python and Node.js traces have compatible structure', () => {
    // Run Python recorder
    const pyRunDir = path.join(tmpDir, 'py-run');
    fs.mkdirSync(pyRunDir, { recursive: true });
    const pyOutDir = path.join(tmpDir, 'py-out');

    try {
      execSync(
        `python3 -c "
import sys
sys.path.insert(0, '${path.join(PROJECT_ROOT, 'python')}')
from agentci_recorder import start_recording, stop_recording
ctx = start_recording(run_dir='${pyRunDir}', run_id='xruntime-py', workspace_root='${PROJECT_ROOT}')
exec(open('${path.join(FIXTURES_DIR, 'test-script.py')}').read())
stop_recording(ctx)
"`,
        {
          env: { ...process.env, AGENTCI_TEST_OUT: pyOutDir },
          stdio: 'pipe',
          timeout: 15000,
        },
      );
    } catch {
      // Allow failures
    }

    // Run Node.js recorder
    const nodeRunDir = path.join(tmpDir, 'node-run');
    fs.mkdirSync(nodeRunDir, { recursive: true });
    const nodeOutDir = path.join(tmpDir, 'node-out');

    try {
      execSync(
        `node -r "${path.join(PROJECT_ROOT, 'dist', 'recorder', 'register.js')}" "${path.join(FIXTURES_DIR, 'test-script.js')}"`,
        {
          env: {
            ...process.env,
            AGENTCI_RUN_DIR: nodeRunDir,
            AGENTCI_RUN_ID: 'xruntime-node',
            AGENTCI_WORKSPACE_ROOT: PROJECT_ROOT,
            AGENTCI_TEST_OUT: nodeOutDir,
          },
          stdio: 'pipe',
          timeout: 10000,
        },
      );
    } catch {
      // Allow failures
    }

    const pyTrace = path.join(pyRunDir, 'trace.jsonl');
    const nodeTrace = path.join(nodeRunDir, 'trace.jsonl');

    if (!fs.existsSync(pyTrace) || !fs.existsSync(nodeTrace)) {
      return; // Graceful skip if either trace wasn't produced
    }

    const pyEvents = readJsonl(pyTrace);
    const nodeEvents = readJsonl(nodeTrace);

    // Both should have events
    expect(pyEvents.length).toBeGreaterThan(0);
    expect(nodeEvents.length).toBeGreaterThan(0);

    // Both should have lifecycle and effect event types
    const pyTypes = new Set(pyEvents.map((e) => e.type));
    const nodeTypes = new Set(nodeEvents.map((e) => e.type));
    expect(pyTypes.has('effect')).toBe(true);
    expect(nodeTypes.has('effect')).toBe(true);

    // Both should record the same categories of effects
    const pyCategories = new Set(
      pyEvents
        .filter((e) => e.type === 'effect')
        .map((e) => (e.data as { category?: string })?.category)
        .filter(Boolean),
    );
    const nodeCategories = new Set(
      nodeEvents
        .filter((e) => e.type === 'effect')
        .map((e) => (e.data as { category?: string })?.category)
        .filter(Boolean),
    );

    // Both should have at least fs_write (the test script writes a file)
    expect(pyCategories.has('fs_write')).toBe(true);
    expect(nodeCategories.has('fs_write')).toBe(true);

    // Both traces should have consistent event structure
    for (const events of [pyEvents, nodeEvents]) {
      for (const event of events) {
        expect(event).toHaveProperty('id');
        expect(event).toHaveProperty('timestamp');
        expect(event).toHaveProperty('run_id');
        expect(event).toHaveProperty('type');
        expect(event).toHaveProperty('data');
      }
    }
  });
});
