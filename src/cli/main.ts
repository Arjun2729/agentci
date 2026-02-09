#!/usr/bin/env node
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { Command } from 'commander';
import chalk from 'chalk';
import yaml from 'yaml';
import { defaultConfig, loadConfig, saveConfig } from '../core/policy/config';
import { summarizeTrace, writeSignature } from '../core/signature/summarize';
import { EffectSignature, PolicyConfig } from '../core/types';
import { diffSignatures } from '../core/diff/diff';
import { evaluatePolicy } from '../core/policy/evaluate';
import { formatFinding, summarizeFindings } from '../core/diff/explain';
import { readJsonl } from '../core/trace/read_jsonl';
import { generateReportHtml } from '../report/html';
import { serveReports } from '../report/serve';
import {
  writeTraceChecksum,
  verifyTraceIntegrity,
  writeSecret,
  loadSecret,
  writeSignatureChecksum,
  verifySignatureIntegrity,
} from '../core/integrity';
import { validateEffectSignature } from '../core/schema';
import { serveDashboard } from '../dashboard/server';
import { findSimilarRuns } from '../core/similarity/search';
import { detectAnomaly } from '../core/similarity/anomaly';

const program = new Command();
const packageJsonPath = path.resolve(__dirname, '..', '..', 'package.json');
const packageJson = fs.existsSync(packageJsonPath)
  ? JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'))
  : { version: '0.0.0' };

program
  .name('agentci')
  .description('CI guardrails / regression tests for agent side effects.')
  .version(packageJson.version)
  .enablePositionalOptions();

function resolveConfigPath(cwd: string): string {
  return path.join(cwd, '.agentci', 'config.yaml');
}

function resolveBaselinePath(cwd: string): string {
  return path.join(cwd, '.agentci', 'baseline.json');
}

function resolveBaselineMetaPath(cwd: string): string {
  return path.join(cwd, '.agentci', 'baseline.meta.json');
}

function getPassThroughArgs(): string[] {
  const idx = process.argv.indexOf('--');
  if (idx === -1) return [];
  return process.argv.slice(idx + 1);
}

function resolveTraceInput(input: string): { tracePath: string; runDir: string } {
  const stats = fs.statSync(input);
  if (stats.isDirectory()) {
    const tracePath = path.join(input, 'trace.jsonl');
    if (!fs.existsSync(tracePath)) {
      throw new Error(`No trace.jsonl found in ${input}`);
    }
    return { tracePath, runDir: input };
  }
  return { tracePath: input, runDir: path.dirname(input) };
}

function resolveSignatureOutput(runDir: string): string {
  return path.join(runDir, 'signature.json');
}

function sha256File(filePath: string): string {
  const content = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha256');
  hash.update(content);
  return hash.digest('hex');
}

function writeJson(filePath: string, payload: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
}

interface PolicyPack {
  name: string;
  description?: string;
  policy?: Partial<PolicyConfig['policy']>;
  normalization?: Partial<PolicyConfig['normalization']>;
  redaction?: Partial<PolicyConfig['redaction']>;
}

function resolvePackPath(nameOrPath: string): string {
  if (nameOrPath.endsWith('.yaml') || nameOrPath.endsWith('.yml') || nameOrPath.includes(path.sep)) {
    return path.resolve(process.cwd(), nameOrPath);
  }
  return path.resolve(__dirname, '..', '..', 'policy-packs', `${nameOrPath}.yaml`);
}

function loadPolicyPack(nameOrPath: string): PolicyPack {
  const packPath = resolvePackPath(nameOrPath);
  if (!fs.existsSync(packPath)) {
    throw new Error(`Policy pack not found: ${packPath}`);
  }
  const raw = fs.readFileSync(packPath, 'utf8');
  const parsed = yaml.parse(raw);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Invalid policy pack at ${packPath}`);
  }
  return parsed as PolicyPack;
}

function mergePack(base: PolicyConfig, pack: PolicyPack): PolicyConfig {
  const merged: PolicyConfig = { ...base };
  if (pack.normalization) {
    merged.normalization = {
      ...base.normalization,
      ...pack.normalization,
      filesystem: {
        ...base.normalization?.filesystem,
        ...(pack.normalization?.filesystem ?? {}),
      },
      network: {
        ...base.normalization?.network,
        ...(pack.normalization?.network ?? {}),
      },
      exec: {
        ...base.normalization?.exec,
        ...(pack.normalization?.exec ?? {}),
      },
    };
  }
  if (pack.redaction) {
    merged.redaction = {
      ...base.redaction,
      ...pack.redaction,
    };
  }
  if (pack.policy) {
    merged.policy = {
      ...base.policy,
      ...pack.policy,
      filesystem: {
        ...base.policy?.filesystem,
        ...(pack.policy?.filesystem ?? {}),
      },
      network: {
        ...base.policy?.network,
        ...(pack.policy?.network ?? {}),
      },
      exec: {
        ...base.policy?.exec,
        ...(pack.policy?.exec ?? {}),
      },
      sensitive: {
        ...base.policy?.sensitive,
        ...(pack.policy?.sensitive ?? {}),
      },
    };
  }
  return merged;
}

function parseFormat(format?: string): 'text' | 'json' {
  if (format && format.toLowerCase() === 'json') return 'json';
  return 'text';
}

function driftHint(category: string): string {
  switch (category) {
    case 'fs_writes':
      return 'New files modified or created.';
    case 'fs_deletes':
      return 'New files deleted.';
    case 'fs_reads_external':
      return 'New external file reads.';
    case 'net_hosts':
      return 'New outbound network destinations.';
    case 'net_protocols':
      return 'New network protocols used.';
    case 'net_ports':
      return 'New network ports used.';
    case 'net_etld_plus_1':
      return 'New top-level domains contacted.';
    case 'exec_commands':
      return 'New subprocesses executed.';
    case 'exec_argv':
      return 'New subprocess argument shapes.';
    case 'sensitive_keys_accessed':
      return 'New sensitive env keys accessed.';
    default:
      return '';
  }
}

function loadSignature(pathInput: string): EffectSignature {
  const raw = JSON.parse(fs.readFileSync(pathInput, 'utf8'));
  if (raw?.meta && !raw.meta.normalization_rules_version) {
    raw.meta.normalization_rules_version = 'legacy';
  }
  if (raw?.effects) {
    if (!raw.effects.net_protocols) raw.effects.net_protocols = [];
    if (!raw.effects.net_ports) raw.effects.net_ports = [];
  }
  const sig = validateEffectSignature(raw);
  if (sig.meta.signature_version !== '1.0') {
    // eslint-disable-next-line no-console
    console.error(
      chalk.yellow(
        `Warning: signature version '${sig.meta.signature_version}' may not be compatible with this CLI (expects '1.0').`,
      ),
    );
  }
  return sig;
}

function initProject(): void {
  const cwd = process.cwd();
  const configPath = resolveConfigPath(cwd);
  const config = defaultConfig('.');
  saveConfig(configPath, config);
  // eslint-disable-next-line no-console
  console.log(chalk.green(`Wrote config to ${configPath}`));

  const agentciDir = path.join(cwd, '.agentci');
  fs.mkdirSync(agentciDir, { recursive: true });
  const secretPath = path.join(agentciDir, 'secret');
  if (!fs.existsSync(secretPath)) {
    writeSecret(agentciDir);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Generated signing secret at ${secretPath}`));
    // eslint-disable-next-line no-console
    console.log(chalk.yellow('Add .agentci/secret to .gitignore — never commit this file.'));
  }
}

program
  .command('init')
  .description('Initialize .agentci config and baseline layout')
  .action(() => {
    initProject();
  });

program
  .command('adopt')
  .description('Write .agentci/config.yaml (alias of init)')
  .action(() => {
    initProject();
  });

program
  .command('record')
  .description('Run a command with the recorder enabled')
  .option('--enforce', 'Fail fast on policy violations')
  .allowUnknownOption(true)
  .passThroughOptions()
  .action((options: { enforce?: boolean }) => {
    const cmdArgs = getPassThroughArgs();
    if (!cmdArgs.length) {
      // eslint-disable-next-line no-console
      console.error(chalk.red('No command provided. Use: agentci record -- <command...>'));
      process.exit(1);
    }

    const cwd = process.cwd();
    const runId = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const runDir = path.join(cwd, '.agentci', 'runs', runId);
    fs.mkdirSync(runDir, { recursive: true, mode: 0o700 });

    const configPath = resolveConfigPath(cwd);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      AGENTCI_RUN_DIR: runDir,
      AGENTCI_RUN_ID: runId,
      AGENTCI_WORKSPACE_ROOT: cwd,
      AGENTCI_VERSION: packageJson.version
    };
    if (options.enforce) {
      env.AGENTCI_ENFORCE = '1';
    }
    if (fs.existsSync(configPath)) {
      env.AGENTCI_CONFIG_PATH = configPath;
    }

    const registerPath = path.resolve(__dirname, '..', 'recorder', 'register.js');
    const registerArg = registerPath.includes(' ') ? `"${registerPath}"` : registerPath;
    const nodeOptions = `${process.env.NODE_OPTIONS || ''} --require ${registerArg}`.trim();

    const child = spawn(cmdArgs[0], cmdArgs.slice(1), {
      stdio: 'inherit',
      env: { ...env, NODE_OPTIONS: nodeOptions }
    });

    child.on('error', (err: unknown) => {
      console.error(chalk.red(`Failed to start command: ${err}`));
      process.exit(1);
    });

    child.on('exit', (code: number | null) => {
      process.exit(code ?? 0);
    });
  });

program
  .command('summarize')
  .description('Derive a signature from a trace or run directory')
  .argument('<trace_or_run_dir>')
  .option('--config <path>', 'Path to config.yaml')
  .action((input: string, options: { config?: string }) => {
    const { tracePath, runDir } = resolveTraceInput(input);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const signature = summarizeTrace(tracePath, config, packageJson.version);
    const outPath = resolveSignatureOutput(runDir);
    writeSignature(outPath, signature);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote signature to ${outPath}`));

    const runId = process.env.AGENTCI_RUN_ID || path.basename(runDir);
    const secret = loadSecret(process.cwd(), runId);
    const signatureChecksumPath = writeSignatureChecksum(outPath, runId, secret);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote signature checksum to ${signatureChecksumPath}`));
    const checksumPath = writeTraceChecksum(tracePath, runId, secret);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote integrity checksum to ${checksumPath}`));
  });

const baselineCmd = program.command('baseline').description('Baseline lifecycle commands');

baselineCmd
  .command('create')
  .description('Create or overwrite baseline.json from a trace or run directory')
  .argument('<trace_or_run_dir>')
  .option('--config <path>', 'Path to config.yaml')
  .option('--reason <text>', 'Reason for baseline update')
  .option('--by <name>', 'Name of the person creating the baseline')
  .option('--pr <link>', 'PR or change link')
  .action((input: string, options: { config?: string; reason?: string; by?: string; pr?: string }) => {
    const { tracePath, runDir } = resolveTraceInput(input);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const signature = summarizeTrace(tracePath, config, packageJson.version);
    const runSigPath = resolveSignatureOutput(runDir);
    writeSignature(runSigPath, signature);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote signature to ${runSigPath}`));

    const runId = process.env.AGENTCI_RUN_ID || path.basename(runDir);
    const secret = loadSecret(process.cwd(), runId);
    const runSigChecksum = writeSignatureChecksum(runSigPath, runId, secret);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote signature checksum to ${runSigChecksum}`));

    const baselinePath = resolveBaselinePath(process.cwd());
    writeSignature(baselinePath, signature);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Updated baseline at ${baselinePath}`));

    const baselineChecksum = writeSignatureChecksum(baselinePath, runId, secret);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote baseline checksum to ${baselineChecksum}`));

    const metaPath = resolveBaselineMetaPath(process.cwd());
    const digest = sha256File(baselinePath);
    const meta = {
      status: 'created',
      created_at: new Date().toISOString(),
      created_by: options.by || process.env.USER || 'unknown',
      reason: options.reason || null,
      pr: options.pr || null,
      policy_version: config.version,
      signature_version: signature.meta.signature_version,
      normalization_rules_version: signature.meta.normalization_rules_version,
      baseline_digest: digest,
    };
    writeJson(metaPath, meta);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote baseline metadata to ${metaPath}`));
  });

baselineCmd
  .command('approve')
  .description('Approve the current baseline with metadata')
  .option('--by <name>', 'Approver name')
  .option('--reason <text>', 'Approval reason')
  .option('--pr <link>', 'PR or change link')
  .action((options: { by?: string; reason?: string; pr?: string }) => {
    const baselinePath = resolveBaselinePath(process.cwd());
    if (!fs.existsSync(baselinePath)) {
      // eslint-disable-next-line no-console
      console.error(chalk.red(`Baseline not found at ${baselinePath}`));
      process.exit(1);
    }
    const metaPath = resolveBaselineMetaPath(process.cwd());
    const existing = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, 'utf8')) : {};
    const digest = sha256File(baselinePath);
    const meta = {
      ...existing,
      status: 'approved',
      approved_at: new Date().toISOString(),
      approved_by: options.by || process.env.USER || 'unknown',
      approval_reason: options.reason || null,
      pr: options.pr || existing.pr || null,
      baseline_digest: digest,
    };
    writeJson(metaPath, meta);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Updated baseline metadata at ${metaPath}`));
  });

baselineCmd
  .command('status')
  .description('Show baseline metadata and digest status')
  .option('--format <format>', 'Output format: text|json', 'text')
  .action((options: { format?: string }) => {
    const baselinePath = resolveBaselinePath(process.cwd());
    const metaPath = resolveBaselineMetaPath(process.cwd());
    const format = parseFormat(options.format);

    if (!fs.existsSync(baselinePath)) {
      const payload = { exists: false };
      if (format === 'json') {
        // eslint-disable-next-line no-console
        console.log(JSON.stringify(payload, null, 2));
        process.exit(1);
      }
      // eslint-disable-next-line no-console
      console.log(chalk.red('Baseline not found.'));
      process.exit(1);
    }

    const digest = sha256File(baselinePath);
    const meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, 'utf8')) : {};
    const matches = meta.baseline_digest ? meta.baseline_digest === digest : null;
    const payload = { exists: true, baseline_digest: digest, metadata: meta, digest_matches_metadata: matches };

    if (format === 'json') {
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(payload, null, 2));
      return;
    }

    // eslint-disable-next-line no-console
    console.log(chalk.bold('BASELINE STATUS'));
    // eslint-disable-next-line no-console
    console.log(`Digest: ${digest}`);
    if (matches === true) {
      console.log(chalk.green('Digest matches metadata.'));
    } else if (matches === false) {
      console.log(chalk.yellow('Digest does not match metadata (baseline changed?).'));
    } else {
      console.log(chalk.gray('No metadata digest found.'));
    }
    if (Object.keys(meta).length) {
      console.log(chalk.bold('\nMETADATA'));
      Object.entries(meta).forEach(([key, value]) => {
        console.log(`${key}: ${value}`);
      });
    }
  });

const policyCmd = program.command('policy').description('Policy pack helpers');

policyCmd
  .command('list')
  .description('List available policy packs')
  .action(() => {
    const packsDir = path.resolve(__dirname, '..', '..', 'policy-packs');
    if (!fs.existsSync(packsDir)) {
      // eslint-disable-next-line no-console
      console.log(chalk.gray('No policy packs found.'));
      return;
    }
    const files = fs.readdirSync(packsDir).filter((file) => file.endsWith('.yaml') || file.endsWith('.yml'));
    if (!files.length) {
      // eslint-disable-next-line no-console
      console.log(chalk.gray('No policy packs found.'));
      return;
    }
    files.forEach((file) => {
      try {
        const pack = loadPolicyPack(file.replace(/\.(yaml|yml)$/i, ''));
        // eslint-disable-next-line no-console
        console.log(`${pack.name}${pack.description ? ` — ${pack.description}` : ''}`);
      } catch {
        // eslint-disable-next-line no-console
        console.log(file);
      }
    });
  });

policyCmd
  .command('show')
  .description('Show a policy pack')
  .argument('<pack>')
  .action((packName: string) => {
    const packPath = resolvePackPath(packName);
    if (!fs.existsSync(packPath)) {
      // eslint-disable-next-line no-console
      console.error(chalk.red(`Policy pack not found: ${packName}`));
      process.exit(1);
    }
    // eslint-disable-next-line no-console
    console.log(fs.readFileSync(packPath, 'utf8'));
  });

policyCmd
  .command('apply')
  .description('Apply a policy pack to .agentci/config.yaml')
  .argument('<pack>')
  .option('--config <path>', 'Path to config.yaml')
  .action((packName: string, options: { config?: string }) => {
    const configPath = options.config || resolveConfigPath(process.cwd());
    const base = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const pack = loadPolicyPack(packName);
    const merged = mergePack(base, pack);
    saveConfig(configPath, merged);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Applied policy pack '${pack.name}' to ${configPath}`));
  });

program
  .command('diff')
  .description('Diff baseline vs current signatures and evaluate policy')
  .argument('<baseline_signature>')
  .argument('<current_signature>')
  .option('--config <path>', 'Path to config.yaml')
  .option('--format <format>', 'Output format: text|json', 'text')
  .action((baselinePath: string, currentPath: string, options: { config?: string; format?: string }) => {
    const baseline = loadSignature(baselinePath);
    const current = loadSignature(currentPath);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());

    const diff = diffSignatures(baseline, current);
    const findings = evaluatePolicy(current, config);
    const summary = summarizeFindings(findings);

    const format = parseFormat(options.format);
    if (format === 'json') {
      const driftHints = Object.fromEntries(
        Object.keys(diff.drift).map((key) => [key, driftHint(key)]),
      );
      const payload = {
        summary,
        findings,
        drift: diff.drift,
        drift_hints: driftHints,
        context: {
          platform: current.meta.platform,
          adapter: current.meta.adapter,
          node: current.meta.node_version,
          normalization_rules_version: current.meta.normalization_rules_version,
        },
      };
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(payload, null, 2));
      if (summary.hasBlock) process.exit(1);
      return;
    }

    const summaryLabel = summary.hasBlock
      ? chalk.red('BLOCK')
      : summary.hasWarn
        ? chalk.yellow('WARN')
        : chalk.green('PASS');

    // eslint-disable-next-line no-console
    console.log(chalk.bold('SUMMARY'), summaryLabel);

    if (findings.length) {
      // eslint-disable-next-line no-console
      console.log(chalk.bold('\nPOLICY VIOLATIONS'));
      findings.forEach((finding) => {
        const color = finding.severity === 'BLOCK' ? chalk.red : finding.severity === 'WARN' ? chalk.yellow : chalk.gray;
        console.log(color(`- ${formatFinding(finding)}`));
      });
    }

    // eslint-disable-next-line no-console
    console.log(chalk.bold('\nDRIFT'));
    const driftEntries = Object.entries(diff.drift).filter(([, values]) => values.length);
    if (!driftEntries.length) {
      console.log(chalk.gray('No drift detected.'));
    } else {
      driftEntries.forEach(([key, values]) => {
        const hint = driftHint(key);
        const label = hint ? `${key} — ${hint}` : key;
        console.log(chalk.cyan(`${label}:`));
        values.forEach((value: string | number) => console.log(`  - ${value}`));
      });
    }

    // eslint-disable-next-line no-console
    console.log(chalk.bold('\nCONTEXT'));
    console.log(`Platform: ${current.meta.platform}`);
    console.log(`Adapter: ${current.meta.adapter}`);
    console.log(`Node: ${current.meta.node_version}`);
    console.log(`Normalization: ${current.meta.normalization_rules_version}`);

    if (summary.hasBlock) {
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Generate a self-contained HTML report')
  .argument('<baseline_signature>')
  .argument('<current_signature>')
  .option('--trace <path>', 'Optional trace.jsonl')
  .option('--out <path>', 'Output HTML path')
  .option('--config <path>', 'Path to config.yaml')
  .action((baselinePath: string, currentPath: string, options: { trace?: string; out?: string; config?: string }) => {
    const baseline = fs.existsSync(baselinePath) ? loadSignature(baselinePath) : null;
    const current = loadSignature(currentPath);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const diff = diffSignatures(baseline, current);
    const findings = evaluatePolicy(current, config);
    const trace = options.trace ? readJsonl(options.trace) : undefined;

    const html = generateReportHtml({ baseline, current, diff, findings, trace });

    const outPath = options.out
      ? options.out
      : path.join(path.dirname(currentPath), 'report.html');
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, html, 'utf8');

    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote report to ${outPath}`));
  });

program
  .command('attest')
  .description('Generate an attestation for a signature + policy verdict')
  .argument('<baseline_signature>')
  .argument('<current_signature>')
  .option('--config <path>', 'Path to config.yaml')
  .option('--out <path>', 'Output attestation path')
  .action((baselinePath: string, currentPath: string, options: { config?: string; out?: string }) => {
    const baseline = fs.existsSync(baselinePath) ? loadSignature(baselinePath) : null;
    const current = loadSignature(currentPath);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const findings = evaluatePolicy(current, config);
    const summary = summarizeFindings(findings);
    const verdict = summary.hasBlock ? 'block' : summary.hasWarn ? 'warn' : 'pass';

    const gitSha =
      process.env.GIT_SHA ||
      process.env.GITHUB_SHA ||
      process.env.CI_COMMIT_SHA ||
      process.env.BUILD_SOURCEVERSION ||
      'unknown';

    const payload = {
      git_sha: gitSha,
      ci_run_id: process.env.CI_RUN_ID || process.env.GITHUB_RUN_ID || 'unknown',
      policy_version: config.version,
      signature_version: current.meta.signature_version,
      normalization_rules_version: current.meta.normalization_rules_version,
      signature_digest: sha256File(currentPath),
      baseline_digest: baseline ? sha256File(baselinePath) : null,
      verdict,
      generated_at: new Date().toISOString(),
    };

    const outPath = options.out ? options.out : path.join(path.dirname(currentPath), 'attestation.json');
    writeJson(outPath, payload);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote attestation to ${outPath}`));

    if (summary.hasBlock) process.exit(1);
  });

program
  .command('evaluate')
  .description('Evaluate a signature against policy')
  .argument('<signature>')
  .option('--config <path>', 'Path to config.yaml')
  .option('--format <format>', 'Output format: text|json', 'text')
  .action((signaturePath: string, options: { config?: string; format?: string }) => {
    const signature = loadSignature(signaturePath);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
    const findings = evaluatePolicy(signature, config);
    const summary = summarizeFindings(findings);
    const format = parseFormat(options.format);

    if (format === 'json') {
      const payload = { summary, findings };
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(payload, null, 2));
      if (summary.hasBlock) process.exit(1);
      return;
    }

    const summaryLabel = summary.hasBlock
      ? chalk.red('BLOCK')
      : summary.hasWarn
        ? chalk.yellow('WARN')
        : chalk.green('PASS');
    // eslint-disable-next-line no-console
    console.log(chalk.bold('SUMMARY'), summaryLabel);
    if (findings.length) {
      // eslint-disable-next-line no-console
      console.log(chalk.bold('\nPOLICY VIOLATIONS'));
      findings.forEach((finding) => {
        const color = finding.severity === 'BLOCK' ? chalk.red : finding.severity === 'WARN' ? chalk.yellow : chalk.gray;
        console.log(color(`- ${formatFinding(finding)}`));
      });
    }
    if (summary.hasBlock) process.exit(1);
  });

program
  .command('verify')
  .description('Verify trace file integrity against its checksum')
  .argument('<trace_or_run_dir>')
  .option('--signature <path>', 'Optional signature.json for attestation checks')
  .option('--baseline <path>', 'Optional baseline.json for attestation checks')
  .option('--attestation <path>', 'Optional attestation.json to validate')
  .option('--config <path>', 'Optional config.yaml to verify policy version')
  .option('--format <format>', 'Output format: text|json', 'text')
  .action((input: string, options: { signature?: string; baseline?: string; attestation?: string; config?: string; format?: string }) => {
    const { tracePath, runDir } = resolveTraceInput(input);
    const runId = path.basename(runDir);
    const secret = loadSecret(process.cwd(), runId);
    const result = verifyTraceIntegrity(tracePath, runId, secret);
    const format = parseFormat(options.format);
    const checks: Record<string, { valid: boolean; details: string }> = {
      trace: result,
    };

    if (options.signature) {
      const sigResult = verifySignatureIntegrity(options.signature, runId, secret);
      checks.signature_integrity = sigResult;
    }

    if (options.attestation) {
      try {
        const attestation = JSON.parse(fs.readFileSync(options.attestation, 'utf8'));
        if (options.signature) {
          const digest = sha256File(options.signature);
          checks.signature = {
            valid: digest === attestation.signature_digest,
            details: digest === attestation.signature_digest ? 'Signature digest match' : 'Signature digest mismatch',
          };
        }
        if (options.baseline) {
          const digest = sha256File(options.baseline);
          checks.baseline = {
            valid: digest === attestation.baseline_digest,
            details: digest === attestation.baseline_digest ? 'Baseline digest match' : 'Baseline digest mismatch',
          };
        }
        if (options.signature) {
          const signature = loadSignature(options.signature);
          checks.policy = {
            valid:
              signature.meta.signature_version === attestation.signature_version &&
              signature.meta.normalization_rules_version === attestation.normalization_rules_version,
            details: 'Signature version/normalization match attestation',
          };
        }
        const configPath = options.config || resolveConfigPath(process.cwd());
        if (fs.existsSync(configPath) && attestation.policy_version !== undefined) {
          const config = loadConfig(configPath, process.cwd());
          checks.policy_version = {
            valid: config.version === attestation.policy_version,
            details: config.version === attestation.policy_version ? 'Policy version match' : 'Policy version mismatch',
          };
        }
      } catch (err) {
        checks.attestation = { valid: false, details: `Failed to load attestation: ${err}` };
      }
    }

    const allValid = Object.values(checks).every((check) => check.valid);
    if (format === 'json') {
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ valid: allValid, checks }, null, 2));
      if (!allValid) process.exit(1);
      return;
    }

    if (allValid) {
      // eslint-disable-next-line no-console
      console.log(chalk.green(`PASS: ${result.details}`));
    } else {
      // eslint-disable-next-line no-console
      console.log(chalk.red(`FAIL: ${result.details}`));
      Object.entries(checks).forEach(([key, check]) => {
        if (check.valid) return;
        // eslint-disable-next-line no-console
        console.log(chalk.red(`- ${key}: ${check.details}`));
      });
      process.exit(1);
    }
  });

program
  .command('serve')
  .description('Serve report HTML files locally')
  .option('--dir <path>', 'Directory of runs', '.agentci/runs')
  .option('--port <port>', 'Port to serve', '8787')
  .action((options: { dir: string; port: string }) => {
    const dir = path.resolve(process.cwd(), options.dir);
    const port = Number(options.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(chalk.red('Invalid port number. Must be 1-65535.'));
      process.exit(1);
    }
    serveReports(dir, port);
  });

program
  .command('dashboard')
  .description('Launch the AgentCI web dashboard')
  .option('--dir <path>', 'Directory of runs', '.agentci/runs')
  .option('--port <port>', 'Port to serve', '8788')
  .action((options: { dir: string; port: string }) => {
    const dir = path.resolve(process.cwd(), options.dir);
    const port = Number(options.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(chalk.red('Invalid port number. Must be 1-65535.'));
      process.exit(1);
    }
    serveDashboard(dir, port);
  });

// --- Remote control plane commands (Pro) ---

const remoteCmd = program.command('remote').description('Remote control plane commands (Pro)');

remoteCmd
  .command('login')
  .description('Save remote server URL and API key')
  .argument('<url>', 'Remote server URL')
  .argument('<api_key>', 'API key')
  .action(async (url: string, apiKey: string) => {
    const { saveRemoteConfig } = await import('../pro/remote/client');
    const agentciDir = path.join(process.cwd(), '.agentci');
    saveRemoteConfig(agentciDir, { url, api_key: apiKey });
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Saved remote config to ${agentciDir}/remote.json`));
  });

remoteCmd
  .command('push')
  .description('Push a run to the remote control plane')
  .argument('<run_dir>', 'Run directory to push')
  .action(async (runDir: string) => {
    const { loadRemoteConfig, pushRun } = await import('../pro/remote/client');
    const { requireFeature } = await import('../core/license');
    const agentciDir = path.join(process.cwd(), '.agentci');
    requireFeature('remote', 'Remote Push', agentciDir);
    const config = loadRemoteConfig(agentciDir);
    if (!config) {
      console.error(chalk.red('No remote config. Run: agentci remote login <url> <api_key>'));
      process.exit(1);
    }
    const result = await pushRun(config.url, config.api_key, path.resolve(runDir));
    if (result.status === 200) {
      // eslint-disable-next-line no-console
      console.log(chalk.green('Run pushed successfully.'));
    } else {
      console.error(chalk.red(`Push failed (${result.status}): ${JSON.stringify(result.body)}`));
      process.exit(1);
    }
  });

remoteCmd
  .command('runs')
  .description('List runs from the remote control plane')
  .action(async () => {
    const { loadRemoteConfig, listRemoteRuns } = await import('../pro/remote/client');
    const { requireFeature } = await import('../core/license');
    const agentciDir = path.join(process.cwd(), '.agentci');
    requireFeature('remote', 'Remote List Runs', agentciDir);
    const config = loadRemoteConfig(agentciDir);
    if (!config) {
      console.error(chalk.red('No remote config. Run: agentci remote login <url> <api_key>'));
      process.exit(1);
    }
    const result = await listRemoteRuns(config.url, config.api_key);
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(result.body, null, 2));
  });

remoteCmd
  .command('serve')
  .description('Start the remote control plane server')
  .option('--data-dir <path>', 'Data directory', '.agentci/remote')
  .option('--keys-file <path>', 'API keys file', '.agentci/remote/keys/api-keys.json')
  .option('--port <port>', 'Port to serve', '9090')
  .action(async (options: { dataDir: string; keysFile: string; port: string }) => {
    const { serveRemote } = await import('../pro/remote/server');
    const agentciDir = path.join(process.cwd(), '.agentci');
    const dataDir = path.resolve(process.cwd(), options.dataDir);
    const keysFile = path.resolve(process.cwd(), options.keysFile);
    const port = Number(options.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(chalk.red('Invalid port number. Must be 1-65535.'));
      process.exit(1);
    }
    serveRemote(dataDir, port, keysFile, agentciDir);
  });

remoteCmd
  .command('keygen')
  .description('Generate a new API key')
  .option('--team <id>', 'Team ID', 'default')
  .option('--name <name>', 'Key name', 'cli-generated')
  .option('--keys-file <path>', 'API keys file', '.agentci/remote/keys/api-keys.json')
  .action(async (options: { team: string; name: string; keysFile: string }) => {
    const { generateApiKey, addApiKey } = await import('../pro/remote/keygen');
    const keysFile = path.resolve(process.cwd(), options.keysFile);
    const key = generateApiKey();
    addApiKey(keysFile, key, options.team, options.name);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Generated API key for team "${options.team}":`));
    // eslint-disable-next-line no-console
    console.log(key);
    // eslint-disable-next-line no-console
    console.log(chalk.yellow('\nStore this key securely — it cannot be retrieved later.'));
  });

// --- Similarity + Anomaly commands ---

program
  .command('similar')
  .description('Find runs most similar to a given signature')
  .argument('<signature_or_run_dir>', 'Signature file or run directory')
  .option('--limit <n>', 'Number of results', '10')
  .option('--runs-dir <path>', 'Runs directory', '.agentci/runs')
  .action((input: string, options: { limit: string; runsDir: string }) => {
    const sig = loadSignature(
      fs.statSync(input).isDirectory() ? path.join(input, 'signature.json') : input,
    );
    const runsDir = path.resolve(process.cwd(), options.runsDir);
    const limit = parseInt(options.limit, 10) || 10;
    const results = findSimilarRuns(sig, runsDir, limit);

    if (!results.length) {
      // eslint-disable-next-line no-console
      console.log(chalk.gray('No similar runs found.'));
      return;
    }

    // eslint-disable-next-line no-console
    console.log(chalk.bold(`Top ${results.length} similar runs:`));
    for (const r of results) {
      const pct = (r.score * 100).toFixed(1);
      const color = r.score > 0.8 ? chalk.green : r.score > 0.5 ? chalk.yellow : chalk.red;
      // eslint-disable-next-line no-console
      console.log(`  ${color(`${pct}%`)}  ${r.run_id}`);
    }
  });

program
  .command('anomaly')
  .description('Detect anomalous behavior in a run')
  .argument('<signature_or_run_dir>', 'Signature file or run directory')
  .option('--threshold <0-1>', 'Anomaly threshold', '0.7')
  .option('--runs-dir <path>', 'Runs directory', '.agentci/runs')
  .action((input: string, options: { threshold: string; runsDir: string }) => {
    const sig = loadSignature(
      fs.statSync(input).isDirectory() ? path.join(input, 'signature.json') : input,
    );
    const runsDir = path.resolve(process.cwd(), options.runsDir);
    const threshold = parseFloat(options.threshold) || 0.7;
    const result = detectAnomaly(sig, runsDir, { threshold });

    if (result.is_anomaly) {
      // eslint-disable-next-line no-console
      console.log(chalk.red(`ANOMALY DETECTED (score: ${(result.score * 100).toFixed(1)}%, threshold: ${(result.threshold * 100).toFixed(1)}%)`));
      // eslint-disable-next-line no-console
      console.log(chalk.bold('Nearest neighbors:'));
      for (const n of result.nearest_neighbors) {
        // eslint-disable-next-line no-console
        console.log(`  ${(n.similarity * 100).toFixed(1)}%  ${n.run_id}`);
      }
      process.exit(1);
    } else {
      // eslint-disable-next-line no-console
      console.log(chalk.green(`NORMAL (score: ${(result.score * 100).toFixed(1)}%, threshold: ${(result.threshold * 100).toFixed(1)}%)`));
    }
  });

program.parse(process.argv);
