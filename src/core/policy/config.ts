import fs from 'fs';
import path from 'path';
import yaml from 'yaml';
import { PolicyConfig } from '../types';
import { safeParsePolicyConfig } from '../schema';

export function defaultConfig(workspaceRoot: string): PolicyConfig {
  return {
    version: 1,
    workspace_root: workspaceRoot,
    normalization: {
      version: '1.0',
      filesystem: {
        collapse_temp: true,
        collapse_home: true,
        ignore_globs: [
          '**/.DS_Store',
          '**/Thumbs.db',
          '**/.git/**',
          '**/.idea/**',
          '**/.vscode/**',
        ],
      },
      network: {
        normalize_hosts: true,
      },
      exec: {
        argv_mode: 'hash',
        mask_patterns: [],
      },
    },
    redaction: {
      redact_paths: [],
      redact_urls: [],
      hash_values: false,
    },
    policy: {
      filesystem: {
        allow_writes: ['./workspace/**', './tmp/**'],
        block_writes: ['/etc/**', '~/**'],
        enforce_allowlist: false
      },
      network: {
        allow_etld_plus_1: [],
        allow_hosts: [],
        enforce_allowlist: true,
        allow_protocols: [],
        block_protocols: [],
        allow_ports: [],
        block_ports: []
      },
      exec: {
        allow_commands: ['git', 'ls', 'echo', 'node', 'npm'],
        block_commands: ['rm', 'curl', 'wget'],
        enforce_allowlist: true
      },
      sensitive: {
        block_env: [
          'AWS_*',
          'GCP_*',
          'AZURE_*',
          'OPENAI_*',
          'ANTHROPIC_*',
          '*_KEY',
          '*_TOKEN',
          '*_SECRET',
          '*_PASSWORD',
          'DATABASE_URL',
          'SLACK_*',
          'GH_*',
          'GITHUB_*'
        ],
        block_file_globs: ['~/.ssh/**', '~/.aws/**', '**/.env*']
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

  const redactionParsed = parsed?.redaction ?? {};
  if (redactionParsed.redact_hosts && !redactionParsed.redact_urls) {
    redactionParsed.redact_urls = redactionParsed.redact_hosts;
  }

  const merged = {
    ...defaultConfig(workspaceRoot),
    ...parsed,
    workspace_root: workspaceRoot,
    normalization: {
      ...defaultConfig(workspaceRoot).normalization,
      ...(parsed?.normalization ?? {}),
      filesystem: {
        ...defaultConfig(workspaceRoot).normalization.filesystem,
        ...(parsed?.normalization?.filesystem ?? {}),
      },
      network: {
        ...defaultConfig(workspaceRoot).normalization.network,
        ...(parsed?.normalization?.network ?? {}),
      },
      exec: {
        ...defaultConfig(workspaceRoot).normalization.exec,
        ...(parsed?.normalization?.exec ?? {}),
      },
    },
    redaction: {
      ...defaultConfig(workspaceRoot).redaction,
      ...redactionParsed,
    },
    policy: {
      ...defaultConfig(workspaceRoot).policy,
      ...(parsed?.policy ?? {}),
      filesystem: {
        ...defaultConfig(workspaceRoot).policy.filesystem,
        ...(parsed?.policy?.filesystem ?? {})
      },
      network: {
        ...defaultConfig(workspaceRoot).policy.network,
        ...(parsed?.policy?.network ?? {})
      },
      exec: {
        ...defaultConfig(workspaceRoot).policy.exec,
        ...(parsed?.policy?.exec ?? {})
      },
      sensitive: {
        ...defaultConfig(workspaceRoot).policy.sensitive,
        ...(parsed?.policy?.sensitive ?? {})
      }
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
