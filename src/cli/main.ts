#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { Command } from 'commander';
import chalk from 'chalk';
import { defaultConfig, loadConfig, saveConfig } from '../core/policy/config';
import { summarizeTrace, writeSignature } from '../core/signature/summarize';
import { EffectSignature } from '../core/types';
import { diffSignatures } from '../core/diff/diff';
import { evaluatePolicy } from '../core/policy/evaluate';
import { formatFinding, summarizeFindings } from '../core/diff/explain';
import { readJsonl } from '../core/trace/read_jsonl';
import { generateReportHtml } from '../report/html';
import { serveReports } from '../report/serve';
import { writeTraceChecksum, verifyTraceIntegrity } from '../core/integrity';
import { validateEffectSignature } from '../core/schema';
import { serveDashboard } from '../dashboard/server';

const program = new Command();
const packageJsonPath = path.resolve(__dirname, '..', '..', 'package.json');
const packageJson = fs.existsSync(packageJsonPath)
  ? JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'))
  : { version: '0.0.0' };

program.name('agentci').version(packageJson.version).enablePositionalOptions();

function resolveConfigPath(cwd: string): string {
  return path.join(cwd, '.agentci', 'config.yaml');
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

function loadSignature(pathInput: string): EffectSignature {
  const raw = JSON.parse(fs.readFileSync(pathInput, 'utf8'));
  return validateEffectSignature(raw);
}

program
  .command('adopt')
  .description('Scan repo and write .agentci/config.yaml')
  .action(() => {
    const cwd = process.cwd();
    const configPath = resolveConfigPath(cwd);
    const config = defaultConfig('.');
    saveConfig(configPath, config);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote config to ${configPath}`));
  });

program
  .command('record')
  .description('Run a command with the recorder enabled')
  .allowUnknownOption(true)
  .passThroughOptions()
  .action(() => {
    const cmdArgs = getPassThroughArgs();
    if (!cmdArgs.length) {
      // eslint-disable-next-line no-console
      console.error(chalk.red('No command provided. Use: agentci record -- <command...>'));
      process.exit(1);
    }

    const cwd = process.cwd();
    const runId = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
    const runDir = path.join(cwd, '.agentci', 'runs', runId);
    fs.mkdirSync(runDir, { recursive: true });

    const configPath = resolveConfigPath(cwd);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      AGENTCI_RUN_DIR: runDir,
      AGENTCI_RUN_ID: runId,
      AGENTCI_WORKSPACE_ROOT: cwd,
      AGENTCI_VERSION: packageJson.version
    };
    if (fs.existsSync(configPath)) {
      env.AGENTCI_CONFIG_PATH = configPath;
    }

    const registerPath = path.resolve(__dirname, '..', 'recorder', 'register.js');
    const registerArg = registerPath.includes(' ') ? `\"${registerPath}\"` : registerPath;
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
    const checksumPath = writeTraceChecksum(tracePath, runId);
    // eslint-disable-next-line no-console
    console.log(chalk.green(`Wrote integrity checksum to ${checksumPath}`));
  });

program
  .command('diff')
  .description('Diff baseline vs current signatures and evaluate policy')
  .argument('<baseline_signature>')
  .argument('<current_signature>')
  .option('--config <path>', 'Path to config.yaml')
  .action((baselinePath: string, currentPath: string, options: { config?: string }) => {
    const baseline = loadSignature(baselinePath);
    const current = loadSignature(currentPath);
    const configPath = options.config || resolveConfigPath(process.cwd());
    const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());

    const diff = diffSignatures(baseline, current);
    const findings = evaluatePolicy(current, config);
    const summary = summarizeFindings(findings);

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
        console.log(chalk.cyan(`${key}:`));
        values.forEach((value: string) => console.log(`  - ${value}`));
      });
    }

    // eslint-disable-next-line no-console
    console.log(chalk.bold('\nCONTEXT'));
    console.log(`Platform: ${current.meta.platform}`);
    console.log(`Adapter: ${current.meta.adapter}`);
    console.log(`Node: ${current.meta.node_version}`);

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
  .command('verify')
  .description('Verify trace file integrity against its checksum')
  .argument('<trace_or_run_dir>')
  .action((input: string) => {
    const { tracePath, runDir } = resolveTraceInput(input);
    const runId = path.basename(runDir);
    const result = verifyTraceIntegrity(tracePath, runId);
    if (result.valid) {
      // eslint-disable-next-line no-console
      console.log(chalk.green(`PASS: ${result.details}`));
    } else {
      // eslint-disable-next-line no-console
      console.log(chalk.red(`FAIL: ${result.details}`));
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
    serveDashboard(dir, port);
  });

program.parse(process.argv);
