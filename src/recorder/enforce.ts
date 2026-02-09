import path from 'path';
import { EffectEventData } from '../core/types';
import { expandTilde, matchHost, matchKey, matchPath, normalizePathForMatch } from '../core/policy/match';
import { normalizeHost } from '../core/normalize';
import { RecorderContext } from './context';
import { toEtldPlus1 } from './canonicalize';

function isAbsolute(p: string): boolean {
  return path.isAbsolute(p) || /^[A-Za-z]:\\/.test(p);
}

function isSubpath(target: string, root: string): boolean {
  const relative = path.relative(root, target);
  if (!relative) return true;
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}

function getWriteCandidate(writePath: string, workspaceRoot: string): string {
  if (isAbsolute(writePath)) {
    return normalizePathForMatch(path.relative(workspaceRoot, writePath));
  }
  return normalizePathForMatch(writePath);
}

function shouldBlock(ctx: RecorderContext, data: EffectEventData): string | null {
  switch (data.category) {
    case 'fs_write': {
      if (!data.fs) return null;
      const writePath = data.fs.path_resolved;
      if (isAbsolute(writePath)) {
        const expanded = expandTilde(writePath);
        if (!isSubpath(expanded, path.resolve(ctx.workspaceRoot))) {
          return `write resolved outside workspace root: ${writePath}`;
        }
      }
      const candidate = getWriteCandidate(writePath, path.resolve(ctx.workspaceRoot));
      if (matchPath(ctx.config.policy.filesystem.block_writes, isAbsolute(writePath) ? expandTilde(writePath) : candidate)) {
        return `write blocked by policy: ${writePath}`;
      }
      if (ctx.config.policy.filesystem.enforce_allowlist && !matchPath(ctx.config.policy.filesystem.allow_writes, candidate)) {
        return `write not in allow_writes: ${writePath}`;
      }
      return null;
    }
    case 'net_outbound': {
      if (!data.net) return null;
      const host = normalizeHost(data.net.host_raw, ctx.config);
      const hostAllowed = matchHost(ctx.config.policy.network.allow_hosts, host);
      const etld = toEtldPlus1(host).toLowerCase();
      const allowedEtlds = ctx.config.policy.network.allow_etld_plus_1.map((value) => value.toLowerCase());
      const hasAllowlist =
        ctx.config.policy.network.allow_hosts.length > 0 || ctx.config.policy.network.allow_etld_plus_1.length > 0;
      if (!hostAllowed && !allowedEtlds.includes(etld) && (ctx.config.policy.network.enforce_allowlist || hasAllowlist)) {
        return `host '${host}' (eTLD+1: ${etld}) not allowed by policy`;
      }
      return null;
    }
    case 'exec': {
      if (!data.exec) return null;
      const argv = data.exec.argv_normalized || [];
      const cmd = argv[0] || data.exec.command_raw;
      if (ctx.config.policy.exec.block_commands.includes(cmd)) {
        return `command '${cmd}' is blocked by policy`;
      }
      if (ctx.config.policy.exec.enforce_allowlist && !ctx.config.policy.exec.allow_commands.includes(cmd)) {
        return `command '${cmd}' not in allow_commands`;
      }
      return null;
    }
    case 'sensitive_access': {
      if (!data.sensitive) return null;
      if (data.sensitive.type === 'env_var' && data.sensitive.key_name) {
        if (matchKey(ctx.config.policy.sensitive.block_env, data.sensitive.key_name)) {
          return `env var '${data.sensitive.key_name}' accessed`;
        }
      }
      if (data.sensitive.type === 'file_read' && data.sensitive.key_name) {
        const expanded = expandTilde(data.sensitive.key_name);
        if (matchPath(ctx.config.policy.sensitive.block_file_globs, expanded)) {
          return `file access '${data.sensitive.key_name}' matches blocked globs`;
        }
      }
      return null;
    }
    default:
      return null;
  }
}

export function enforceEffect(ctx: RecorderContext, data: EffectEventData): void {
  if (!ctx.enforce) return;
  const reason = shouldBlock(ctx, data);
  if (!reason) return;
  // eslint-disable-next-line no-console
  console.error(`[agentci] POLICY BLOCK: ${reason}`);
  ctx.writer.flush();
  process.exit(1);
}
