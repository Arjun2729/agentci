import fs from 'fs';
import path from 'path';
import { EffectEventData, EffectSignature, PolicyConfig, TraceEvent } from '../types';
import { readJsonl } from '../trace/read_jsonl';
import { toEtldPlus1, toWorkspacePath } from '../../recorder/canonicalize';
import { normalizeExecArgv, normalizeExecCommand, normalizeFsPath, normalizeHost } from '../normalize';

function sorted(values: Set<string>): string[] {
  return Array.from(values).filter(Boolean).sort();
}

function detectAdapter(events: TraceEvent[]): 'node-hook' | 'openclaw+node-hook' {
  return events.some((event) => event.type === 'tool_call' || event.type === 'tool_result')
    ? 'openclaw+node-hook'
    : 'node-hook';
}

export function summarizeTrace(tracePath: string, config: PolicyConfig, agentciVersion: string): EffectSignature {
  const events = readJsonl(tracePath);
  const effects = {
    fs_writes: new Set<string>(),
    fs_reads_external: new Set<string>(),
    fs_deletes: new Set<string>(),
    net_etld_plus_1: new Set<string>(),
    net_hosts: new Set<string>(),
    exec_commands: new Set<string>(),
    exec_argv: new Set<string>(),
    sensitive_keys_accessed: new Set<string>()
  };

  for (const event of events) {
    if (event.type !== 'effect') continue;
    const data = event.data as EffectEventData;
    if (!data || !data.category) continue;

    switch (data.category) {
      case 'fs_write': {
        if (!data.fs) break;
        const entry = toWorkspacePath(data.fs.path_resolved, config.workspace_root);
        const normalized = normalizeFsPath(entry.value, config);
        if (normalized) effects.fs_writes.add(normalized);
        break;
      }
      case 'fs_delete': {
        if (!data.fs) break;
        const entry = toWorkspacePath(data.fs.path_resolved, config.workspace_root);
        const normalized = normalizeFsPath(entry.value, config);
        if (normalized) effects.fs_deletes.add(normalized);
        break;
      }
      case 'fs_read': {
        if (!data.fs) break;
        const entry = toWorkspacePath(data.fs.path_resolved, config.workspace_root);
        if (entry.isExternal || !data.fs.is_workspace_local) {
          const normalized = normalizeFsPath(entry.value, config);
          if (normalized) effects.fs_reads_external.add(normalized);
        }
        break;
      }
      case 'net_outbound': {
        if (!data.net) break;
        const host = normalizeHost(data.net.host_raw, config);
        effects.net_hosts.add(host);
        effects.net_etld_plus_1.add(toEtldPlus1(host));
        break;
      }
      case 'exec': {
        if (!data.exec) break;
        const argv = data.exec.argv_normalized || [];
        const normalizedArgv = normalizeExecArgv(argv, config);
        const cmd = normalizeExecCommand(normalizedArgv[0] || data.exec.command_raw);
        effects.exec_commands.add(cmd);
        effects.exec_argv.add(JSON.stringify(normalizedArgv));
        break;
      }
      case 'sensitive_access': {
        if (!data.sensitive) break;
        if (data.sensitive.key_name) {
          effects.sensitive_keys_accessed.add(data.sensitive.key_name);
        }
        break;
      }
      default:
        break;
    }
  }

  const signature: EffectSignature = {
    meta: {
      signature_version: '1.0',
      normalization_rules_version: config.normalization.version,
      agentci_version: agentciVersion,
      platform: `${process.platform}-${process.arch}`,
      adapter: detectAdapter(events),
      scenario_id: 'default',
      node_version: process.version
    },
    effects: {
      fs_writes: sorted(effects.fs_writes),
      fs_reads_external: sorted(effects.fs_reads_external),
      fs_deletes: sorted(effects.fs_deletes),
      net_etld_plus_1: sorted(effects.net_etld_plus_1),
      net_hosts: sorted(effects.net_hosts),
      exec_commands: sorted(effects.exec_commands),
      exec_argv: sorted(effects.exec_argv),
      sensitive_keys_accessed: sorted(effects.sensitive_keys_accessed)
    }
  };

  return signature;
}

export function writeSignature(pathOut: string, signature: EffectSignature): void {
  fs.mkdirSync(path.dirname(pathOut), { recursive: true });
  fs.writeFileSync(pathOut, JSON.stringify(signature, null, 2), 'utf8');
}
