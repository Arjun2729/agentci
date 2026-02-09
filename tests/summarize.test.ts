import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { summarizeTrace } from '../src/core/signature/summarize';
import { PolicyConfig, TraceEvent } from '../src/core/types';

function writeTrace(filePath: string, events: TraceEvent[]) {
  const content = events.map((e) => JSON.stringify(e)).join('\n');
  fs.writeFileSync(filePath, content + '\n', 'utf8');
}

describe('summarize', () => {
  it('derives signature from trace', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentci-trace-'));
    const tracePath = path.join(dir, 'trace.jsonl');
    const events: TraceEvent[] = [
      {
        id: '1',
        timestamp: Date.now(),
        run_id: 'run1',
        type: 'effect',
        data: {
          category: 'fs_write',
          kind: 'observed',
          fs: {
            path_requested: 'workspace/output.txt',
            path_resolved: path.join(dir, 'workspace/output.txt'),
            is_workspace_local: true,
          },
        },
      },
      {
        id: '2',
        timestamp: Date.now(),
        run_id: 'run1',
        type: 'effect',
        data: {
          category: 'net_outbound',
          kind: 'observed',
          net: {
            host_raw: 'api.weather.com',
            host_etld_plus_1: 'weather.com',
            method: 'GET',
            protocol: 'https',
          },
        },
      },
    ];
    writeTrace(tracePath, events);

    const config: PolicyConfig = {
      version: 1,
      workspace_root: dir,
      normalization: {
        version: '1.0',
        filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: [] },
        network: { normalize_hosts: true },
        exec: { argv_mode: 'hash', mask_patterns: [] },
      },
      redaction: { redact_paths: [], redact_urls: [], hash_values: false },
      policy: {
        filesystem: { allow_writes: [], block_writes: [], enforce_allowlist: false },
        network: {
          allow_etld_plus_1: [],
          allow_hosts: [],
          enforce_allowlist: true,
          allow_protocols: [],
          block_protocols: [],
          allow_ports: [],
          block_ports: [],
        },
        exec: { allow_commands: [], block_commands: [], enforce_allowlist: true },
        sensitive: { block_env: [], block_file_globs: [] },
      },
      reporting: { explain_templates: true },
    };

    const signature = summarizeTrace(tracePath, config, '0.1.0');
    expect(signature.effects.fs_writes.length).toBe(1);
    expect(signature.effects.net_etld_plus_1).toContain('weather.com');
  });
});
