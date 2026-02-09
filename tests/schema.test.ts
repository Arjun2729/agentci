import { describe, it, expect } from 'vitest';
import {
  validatePolicyConfig,
  safeParsePolicyConfig,
  validateTraceEvent,
  validateEffectSignature,
} from '../src/core/schema';

describe('schema validation', () => {
  describe('PolicyConfig', () => {
    it('accepts a valid config', () => {
      const valid = {
        version: 1,
        workspace_root: '.',
        normalization: {
          version: '1.0',
          filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: [] },
          network: { normalize_hosts: true },
          exec: { argv_mode: 'hash', mask_patterns: [] },
        },
        redaction: { redact_paths: [], redact_urls: [], hash_values: false },
        policy: {
          filesystem: { allow_writes: ['./workspace/**'], block_writes: ['/etc/**'], enforce_allowlist: false },
          network: {
            allow_etld_plus_1: ['google.com'],
            allow_hosts: ['*.google.com'],
            enforce_allowlist: true,
            allow_protocols: [],
            block_protocols: [],
            allow_ports: [],
            block_ports: [],
          },
          exec: { allow_commands: ['node'], block_commands: ['rm'], enforce_allowlist: true },
          sensitive: { block_env: ['AWS_SECRET_ACCESS_KEY'], block_file_globs: ['~/.ssh/**'] },
        },
      };
      expect(() => validatePolicyConfig(valid)).not.toThrow();
    });

    it('rejects config with missing fields', () => {
      const invalid = { version: 1, workspace_root: '.' };
      const result = safeParsePolicyConfig(invalid);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errors.length).toBeGreaterThan(0);
      }
    });

    it('rejects config with wrong types', () => {
      const invalid = {
        version: 'one',
        workspace_root: '.',
        normalization: {
          version: '1.0',
          filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: [] },
          network: { normalize_hosts: true },
          exec: { argv_mode: 'hash', mask_patterns: [] },
        },
        redaction: { redact_paths: [], redact_urls: [], hash_values: false },
        policy: {
          filesystem: { allow_writes: 'not-array', block_writes: [] },
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
      };
      const result = safeParsePolicyConfig(invalid);
      expect(result.success).toBe(false);
    });

    it('returns detailed error messages for invalid fields', () => {
      const invalid = {
        version: 1,
        workspace_root: '.',
        normalization: {
          version: '1.0',
          filesystem: { collapse_temp: true, collapse_home: true, ignore_globs: [] },
          network: { normalize_hosts: true },
          exec: { argv_mode: 'hash', mask_patterns: [] },
        },
        redaction: { redact_paths: [], redact_urls: [], hash_values: false },
        policy: {
          filesystem: { allow_writes: [123], block_writes: [] },
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
      };
      const result = safeParsePolicyConfig(invalid);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.errors.some((e) => e.includes('allow_writes'))).toBe(true);
      }
    });
  });

  describe('TraceEvent', () => {
    it('accepts a valid trace event', () => {
      const valid = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        timestamp: Date.now(),
        run_id: 'run-1',
        type: 'lifecycle',
        data: { stage: 'start' },
      };
      expect(() => validateTraceEvent(valid)).not.toThrow();
    });

    it('rejects event with invalid type', () => {
      const invalid = {
        id: '123',
        timestamp: Date.now(),
        run_id: 'run-1',
        type: 'invalid_type',
        data: {},
      };
      expect(() => validateTraceEvent(invalid)).toThrow();
    });
  });

  describe('EffectSignature', () => {
    it('accepts a valid signature', () => {
      const valid = {
        meta: {
          signature_version: '1.0',
          normalization_rules_version: '1.0',
          agentci_version: '0.1.0',
          platform: 'darwin-arm64',
          adapter: 'node-hook',
          scenario_id: 'default',
          node_version: 'v18.17.0',
        },
        effects: {
          fs_writes: ['file.txt'],
          fs_reads_external: [],
          fs_deletes: [],
          net_protocols: [],
          net_etld_plus_1: [],
          net_hosts: [],
          net_ports: [],
          exec_commands: [],
          exec_argv: [],
          sensitive_keys_accessed: [],
        },
      };
      expect(() => validateEffectSignature(valid)).not.toThrow();
    });

    it('rejects signature with invalid adapter', () => {
      const invalid = {
        meta: {
          signature_version: '1.0',
          normalization_rules_version: '1.0',
          agentci_version: '0.1.0',
          platform: 'darwin-arm64',
          adapter: 'unknown-adapter',
          scenario_id: 'default',
          node_version: 'v18.17.0',
        },
        effects: {
          fs_writes: [],
          fs_reads_external: [],
          fs_deletes: [],
          net_protocols: [],
          net_etld_plus_1: [],
          net_hosts: [],
          net_ports: [],
          exec_commands: [],
          exec_argv: [],
          sensitive_keys_accessed: [],
        },
      };
      expect(() => validateEffectSignature(invalid)).toThrow();
    });
  });
});
