import fc from 'fast-check';
import type { TraceEvent, EffectCategory, EffectEventData, EffectSignature } from '../../src/core/types';

export function arbitraryPath(): fc.Arbitrary<string> {
  return fc.oneof(
    // Absolute Unix paths
    fc.array(fc.stringOf(fc.char().filter(c => c !== '/' && c !== '\0'), { minLength: 1, maxLength: 20 }), { minLength: 1, maxLength: 6 })
      .map(parts => '/' + parts.join('/')),
    // Relative workspace paths
    fc.array(fc.stringOf(fc.char().filter(c => c !== '/' && c !== '\0'), { minLength: 1, maxLength: 15 }), { minLength: 1, maxLength: 4 })
      .map(parts => './workspace/' + parts.join('/')),
    // Home-relative paths
    fc.array(fc.stringOf(fc.char().filter(c => c !== '/' && c !== '\0'), { minLength: 1, maxLength: 12 }), { minLength: 1, maxLength: 3 })
      .map(parts => '~/' + parts.join('/')),
  );
}

export function arbitraryHostname(): fc.Arbitrary<string> {
  return fc.oneof(
    // Simple hostnames
    fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'.split('')), { minLength: 3, maxLength: 15 })
      .map(s => s + '.com'),
    // Subdomains
    fc.tuple(
      fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'.split('')), { minLength: 2, maxLength: 8 }),
      fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'.split('')), { minLength: 2, maxLength: 10 }),
    ).map(([sub, domain]) => `${sub}.${domain}.com`),
    // Known hosts
    fc.constantFrom('api.openai.com', 'registry.npmjs.org', 'github.com', 'localhost'),
  );
}

export function arbitraryCommand(): fc.Arbitrary<string> {
  return fc.oneof(
    fc.constantFrom('node', 'npm', 'git', 'ls', 'echo', 'python', 'tsc', 'eslint'),
    fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz-_'.split('')), { minLength: 2, maxLength: 15 }),
  );
}

export function arbitraryFsEvent(runId: string): fc.Arbitrary<TraceEvent> {
  return fc.tuple(arbitraryPath(), fc.constantFrom('fs_write', 'fs_read', 'fs_delete') as fc.Arbitrary<EffectCategory>)
    .map(([p, category]) => ({
      id: `evt_${Math.random().toString(36).slice(2, 10)}`,
      timestamp: Date.now(),
      run_id: runId,
      type: 'effect' as const,
      data: {
        category,
        kind: 'observed' as const,
        fs: { path_requested: p, path_resolved: p, is_workspace_local: p.startsWith('./') },
      } satisfies EffectEventData,
    }));
}

export function arbitraryNetEvent(runId: string): fc.Arbitrary<TraceEvent> {
  return fc.tuple(arbitraryHostname(), fc.constantFrom('GET', 'POST', 'PUT', 'DELETE'), fc.constantFrom('http', 'https') as fc.Arbitrary<'http' | 'https'>)
    .map(([host, method, protocol]) => ({
      id: `evt_${Math.random().toString(36).slice(2, 10)}`,
      timestamp: Date.now(),
      run_id: runId,
      type: 'effect' as const,
      data: {
        category: 'net_outbound' as const,
        kind: 'observed' as const,
        net: { host_raw: host, host_etld_plus_1: host, method, protocol },
      } satisfies EffectEventData,
    }));
}

export function arbitraryExecEvent(runId: string): fc.Arbitrary<TraceEvent> {
  return fc.tuple(arbitraryCommand(), fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 0, maxLength: 5 }))
    .map(([cmd, args]) => ({
      id: `evt_${Math.random().toString(36).slice(2, 10)}`,
      timestamp: Date.now(),
      run_id: runId,
      type: 'effect' as const,
      data: {
        category: 'exec' as const,
        kind: 'observed' as const,
        exec: { command_raw: cmd, argv_normalized: [cmd, ...args] },
      } satisfies EffectEventData,
    }));
}

export function arbitrarySensitiveEvent(runId: string): fc.Arbitrary<TraceEvent> {
  return fc.constantFrom('OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'DB_PASSWORD', 'MY_SECRET')
    .map(key => ({
      id: `evt_${Math.random().toString(36).slice(2, 10)}`,
      timestamp: Date.now(),
      run_id: runId,
      type: 'effect' as const,
      data: {
        category: 'sensitive_access' as const,
        kind: 'observed' as const,
        sensitive: { type: 'env_var' as const, key_name: key },
      } satisfies EffectEventData,
    }));
}

export function arbitraryTraceEvent(runId: string = 'test-run'): fc.Arbitrary<TraceEvent> {
  return fc.oneof(
    arbitraryFsEvent(runId),
    arbitraryNetEvent(runId),
    arbitraryExecEvent(runId),
    arbitrarySensitiveEvent(runId),
  );
}

export function arbitraryEffectSignature(): fc.Arbitrary<EffectSignature> {
  return fc.record({
    meta: fc.constant({
      signature_version: '1.0' as const,
      normalization_rules_version: '1.0',
      agentci_version: '0.1.0',
      platform: 'linux-x64',
      adapter: 'node-hook' as const,
      scenario_id: 'default',
      node_version: 'v20.0.0',
    }),
    effects: fc.record({
      fs_writes: fc.array(arbitraryPath(), { maxLength: 10 }).map(arr => [...new Set(arr)].sort()),
      fs_reads_external: fc.array(arbitraryPath(), { maxLength: 5 }).map(arr => [...new Set(arr)].sort()),
      fs_deletes: fc.array(arbitraryPath(), { maxLength: 3 }).map(arr => [...new Set(arr)].sort()),
      net_protocols: fc.subarray(['http', 'https']).map(arr => arr.sort()),
      net_etld_plus_1: fc.array(arbitraryHostname(), { maxLength: 5 }).map(arr => [...new Set(arr)].sort()),
      net_hosts: fc.array(arbitraryHostname(), { maxLength: 5 }).map(arr => [...new Set(arr)].sort()),
      net_ports: fc.subarray([80, 443, 8080, 3000]).map(arr => arr.sort((a, b) => a - b)),
      exec_commands: fc.array(arbitraryCommand(), { maxLength: 5 }).map(arr => [...new Set(arr)].sort()),
      exec_argv: fc.array(fc.json(), { maxLength: 3 }).map(arr => [...new Set(arr)].sort()),
      sensitive_keys_accessed: fc.subarray(['OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN']).map(arr => arr.sort()),
    }),
  });
}

export function defaultConfig() {
  return {
    version: 1,
    workspace_root: '.',
    normalization: {
      version: '1.0',
      filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: ['**/.DS_Store', '**/.git/**'] },
      network: { normalize_hosts: true },
      exec: { argv_mode: 'hash' as const, mask_patterns: [] },
    },
    redaction: { redact_paths: [], redact_urls: [], hash_values: false },
    policy: {
      filesystem: { allow_writes: ['./workspace/**'], block_writes: ['/etc/**'], enforce_allowlist: false },
      network: { allow_etld_plus_1: [], allow_hosts: [], enforce_allowlist: false, allow_protocols: [], block_protocols: [], allow_ports: [], block_ports: [] },
      exec: { allow_commands: ['node', 'npm', 'git'], block_commands: ['rm'], enforce_allowlist: false },
      sensitive: { block_env: ['AWS_*', 'OPENAI_*'], block_file_globs: ['~/.ssh/**'] },
    },
  };
}
