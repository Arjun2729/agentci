import fs from 'fs';
import path from 'path';
import yaml from 'yaml';
import { PolicyConfig } from '../types';
import { safeParsePolicyConfig } from '../schema';

export function defaultConfig(workspaceRoot: string): PolicyConfig {
  return {
    version: 1,
    workspace_root: workspaceRoot,
    policy: {
      filesystem: {
        allow_writes: ['./workspace/**', './tmp/**'],
        block_writes: ['/etc/**', '~/**']
      },
      network: {
        allow_etld_plus_1: ['google.com', 'weatherapi.com'],
        allow_hosts: ['*.google.com', 'api.weather.com']
      },
      exec: {
        allow_commands: ['git', 'ls', 'echo', 'node', 'npm'],
        block_commands: ['rm', 'curl', 'wget']
      },
      sensitive: {
        block_env: ['AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID'],
        block_file_globs: ['~/.ssh/**', '~/.aws/**']
      }
    },
    reporting: {
      explain_templates: true
    }
  };
}

export function loadConfig(configPath: string | undefined, workspaceRootFallback: string): PolicyConfig {
  if (!configPath) {
    return defaultConfig(workspaceRootFallback);
  }

  if (!fs.existsSync(configPath)) {
    return defaultConfig(workspaceRootFallback);
  }

  const raw = fs.readFileSync(configPath, 'utf8');
  const parsed = yaml.parse(raw);

  const workspaceRoot = parsed?.workspace_root
    ? path.resolve(workspaceRootFallback, parsed.workspace_root)
    : workspaceRootFallback;

  const merged = {
    ...defaultConfig(workspaceRoot),
    ...parsed,
    workspace_root: workspaceRoot,
    policy: {
      ...defaultConfig(workspaceRoot).policy,
      ...(parsed?.policy ?? {})
    },
    reporting: {
      ...defaultConfig(workspaceRoot).reporting,
      ...(parsed?.reporting ?? {})
    }
  };

  const validation = safeParsePolicyConfig(merged);
  if (!validation.success) {
    const errorMsg = `Invalid config at ${configPath}:\n  ${validation.errors.join('\n  ')}`;
    // eslint-disable-next-line no-console
    console.error(errorMsg);
    // eslint-disable-next-line no-console
    console.error('Falling back to default config.');
    return defaultConfig(workspaceRootFallback);
  }

  return merged;
}

export function saveConfig(configPath: string, config: PolicyConfig): void {
  const serialized = yaml.stringify(config);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, serialized, 'utf8');
}
