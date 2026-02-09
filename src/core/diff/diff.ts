import { DiffResult, EffectSignature, DriftResult } from '../types';

function diffSet(current: string[], baseline: string[] | null): string[] {
  const base = new Set(baseline ?? []);
  return current.filter((value) => !base.has(value));
}

export function diffSignatures(baseline: EffectSignature | null, current: EffectSignature): DiffResult {
  const drift: DriftResult = {
    fs_writes: diffSet(current.effects.fs_writes, baseline?.effects.fs_writes ?? null),
    fs_reads_external: diffSet(current.effects.fs_reads_external, baseline?.effects.fs_reads_external ?? null),
    fs_deletes: diffSet(current.effects.fs_deletes, baseline?.effects.fs_deletes ?? null),
    net_protocols: diffSet(current.effects.net_protocols ?? [], baseline?.effects.net_protocols ?? null),
    net_etld_plus_1: diffSet(current.effects.net_etld_plus_1, baseline?.effects.net_etld_plus_1 ?? null),
    net_hosts: diffSet(current.effects.net_hosts, baseline?.effects.net_hosts ?? null),
    net_ports: diffSet((current.effects.net_ports ?? []).map(String), baseline?.effects.net_ports?.map(String) ?? null)
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value)),
    exec_commands: diffSet(current.effects.exec_commands, baseline?.effects.exec_commands ?? null),
    exec_argv: diffSet(current.effects.exec_argv, baseline?.effects.exec_argv ?? null),
    sensitive_keys_accessed: diffSet(
      current.effects.sensitive_keys_accessed,
      baseline?.effects.sensitive_keys_accessed ?? null,
    ),
  };

  return { baseline, current, drift };
}
