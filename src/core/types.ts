export type TraceEventType = 'lifecycle' | 'tool_call' | 'tool_result' | 'effect';

export type EffectCategory =
  | 'fs_write'
  | 'fs_read'
  | 'fs_delete'
  | 'net_outbound'
  | 'exec'
  | 'sensitive_access';

export type EffectKind = 'declared' | 'observed' | 'inferred';

export interface FsEffectData {
  path_requested: string;
  path_resolved: string;
  is_workspace_local: boolean;
}

export interface NetEffectData {
  host_raw: string;
  host_etld_plus_1: string;
  method: string;
  protocol: 'http' | 'https';
}

export interface ExecEffectData {
  command_raw: string;
  argv_normalized: string[];
}

export interface SensitiveEffectData {
  type: 'env_var' | 'file_read';
  key_name?: string;
}

export interface EffectEventData {
  category: EffectCategory;
  kind: EffectKind;
  fs?: FsEffectData;
  net?: NetEffectData;
  exec?: ExecEffectData;
  sensitive?: SensitiveEffectData;
}

export interface TraceEvent {
  id: string;
  timestamp: number;
  run_id: string;
  type: TraceEventType;
  data: unknown;
  metadata?: Record<string, unknown>;
}

export interface EffectSignature {
  meta: {
    signature_version: '1.0';
    normalization_rules_version: string;
    agentci_version: string;
    platform: string;
    adapter: 'node-hook' | 'openclaw+node-hook';
    scenario_id: string;
    node_version: string;
  };
  effects: {
    fs_writes: string[];
    fs_reads_external: string[];
    fs_deletes: string[];
    net_etld_plus_1: string[];
    net_hosts: string[];
    exec_commands: string[];
    exec_argv: string[];
    sensitive_keys_accessed: string[];
  };
}

export interface PolicyConfig {
  version: number;
  workspace_root: string;
  normalization: {
    version: string;
    filesystem: {
      collapse_temp: boolean;
      collapse_home: boolean;
      ignore_globs: string[];
    };
    network: {
      normalize_hosts: boolean;
    };
    exec: {
      argv_mode: 'full' | 'hash' | 'none';
      mask_patterns: string[];
    };
  };
  policy: {
    filesystem: {
      allow_writes: string[];
      block_writes: string[];
      enforce_allowlist: boolean;
    };
    network: {
      allow_etld_plus_1: string[];
      allow_hosts: string[];
      enforce_allowlist: boolean;
    };
    exec: {
      allow_commands: string[];
      block_commands: string[];
      enforce_allowlist: boolean;
    };
    sensitive: {
      block_env: string[];
      block_file_globs: string[];
    };
  };
  reporting?: {
    explain_templates?: boolean;
  };
}

export type Severity = 'INFO' | 'WARN' | 'BLOCK';

export interface PolicyFinding {
  severity: Severity;
  category: string;
  message: string;
  suggestion?: string;
  evidence?: Record<string, unknown>;
}

export interface DriftResult {
  fs_writes: string[];
  fs_reads_external: string[];
  fs_deletes: string[];
  net_etld_plus_1: string[];
  net_hosts: string[];
  exec_commands: string[];
  exec_argv: string[];
  sensitive_keys_accessed: string[];
}

export interface DiffResult {
  baseline: EffectSignature | null;
  current: EffectSignature;
  drift: DriftResult;
}
