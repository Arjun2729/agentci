import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as https from 'https';

export interface RemoteConfig {
  url: string;
  api_key: string;
}

export function loadRemoteConfig(agentciDir: string): RemoteConfig | null {
  const configPath = path.join(agentciDir, 'remote.json');
  try {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } catch {
    return null;
  }
}

export function saveRemoteConfig(agentciDir: string, config: RemoteConfig): void {
  const configPath = path.join(agentciDir, 'remote.json');
  fs.mkdirSync(agentciDir, { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { encoding: 'utf8', mode: 0o600 });
}

function request(
  method: string,
  url: string,
  apiKey: string,
  body?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;

    const req = mod.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
        });
        res.on('end', () => resolve({ status: res.statusCode || 0, body: data }));
      },
    );

    req.on('error', reject);
    req.setTimeout(30_000, () => {
      req.destroy(new Error('Request timeout'));
    });

    if (body) req.write(body);
    req.end();
  });
}

export async function pushRun(
  remoteUrl: string,
  apiKey: string,
  runDir: string,
): Promise<{ status: number; body: unknown }> {
  const sigPath = path.join(runDir, 'signature.json');
  const findingsPath = path.join(runDir, 'findings.json');
  const attestationPath = path.join(runDir, 'attestation.json');

  const signature = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
  const findings = fs.existsSync(findingsPath) ? JSON.parse(fs.readFileSync(findingsPath, 'utf8')) : [];
  const attestation = fs.existsSync(attestationPath) ? JSON.parse(fs.readFileSync(attestationPath, 'utf8')) : undefined;

  const runId = path.basename(runDir);
  const payload = { run_id: runId, signature, findings, attestation };

  const result = await request('POST', `${remoteUrl}/api/push`, apiKey, JSON.stringify(payload));
  return { status: result.status, body: JSON.parse(result.body) };
}

export async function listRemoteRuns(remoteUrl: string, apiKey: string): Promise<{ status: number; body: unknown }> {
  const result = await request('GET', `${remoteUrl}/api/runs`, apiKey);
  return { status: result.status, body: JSON.parse(result.body) };
}

export async function getRemoteRun(
  remoteUrl: string,
  apiKey: string,
  runId: string,
): Promise<{ status: number; body: unknown }> {
  const result = await request('GET', `${remoteUrl}/api/runs/${encodeURIComponent(runId)}`, apiKey);
  return { status: result.status, body: JSON.parse(result.body) };
}
