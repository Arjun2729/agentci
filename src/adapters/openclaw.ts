import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { TraceEvent } from '../core/types';

function now(): number {
  return Date.now();
}

function getTracePath(): string | null {
  const runDir = process.env.AGENTCI_RUN_DIR;
  if (!runDir) return null;
  return path.join(runDir, 'trace.jsonl');
}

function append(event: TraceEvent): void {
  const tracePath = getTracePath();
  if (!tracePath) return;
  try {
    fs.appendFileSync(tracePath, `${JSON.stringify(event)}\n`, 'utf8');
  } catch (err) {
    // best-effort
  }
}

export function emitToolCall(name: string, input: unknown, runId?: string): void {
  append({
    id: randomUUID(),
    timestamp: now(),
    run_id: runId || process.env.AGENTCI_RUN_ID || 'unknown',
    type: 'tool_call',
    data: { name, input, kind: 'declared' }
  });
}

export function emitToolResult(name: string, output: unknown, runId?: string): void {
  append({
    id: randomUUID(),
    timestamp: now(),
    run_id: runId || process.env.AGENTCI_RUN_ID || 'unknown',
    type: 'tool_result',
    data: { name, output, kind: 'declared' }
  });
}
