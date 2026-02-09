import http from 'http';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import { lookupApiKey } from './keygen.js';
import { requireFeature } from '../../core/license.js';

const MAX_BODY_SIZE = 1_024_000; // 1MB
const RATE_LIMIT_PER_MIN = 60;

interface RateEntry { count: number; windowStart: number }

const rateLimiter = new Map<string, RateEntry>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimiter.get(ip);
  if (!entry || now - entry.windowStart >= 60_000) {
    rateLimiter.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_PER_MIN;
}

const PushRunSchema = z.object({
  run_id: z.string().min(1).max(200),
  signature: z.record(z.string(), z.unknown()),
  findings: z.array(z.record(z.string(), z.unknown())).optional().default([]),
  attestation: z.record(z.string(), z.unknown()).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk: Buffer) => {
      data += chunk.toString();
      if (data.length > MAX_BODY_SIZE) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function jsonResponse(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

export function serveRemote(dataDir: string, port: number, keysFile: string, agentciDir?: string): http.Server {
  requireFeature('remote', 'Remote Control Plane', agentciDir);

  fs.mkdirSync(path.join(dataDir, 'runs'), { recursive: true });

  const server = http.createServer(async (req, res) => {
    const url = req.url || '/';
    const method = req.method || 'GET';
    const clientIp = req.socket.remoteAddress || 'unknown';

    if (!checkRateLimit(clientIp)) {
      jsonResponse(res, 429, { error: 'Too many requests' });
      return;
    }

    // Health check (no auth required)
    if (url === '/healthz') {
      jsonResponse(res, 200, { status: 'ok' });
      return;
    }

    // Auth check for all /api/* routes
    if (url.startsWith('/api/')) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        jsonResponse(res, 401, { error: 'Missing API key. Use Authorization: Bearer <key>' });
        return;
      }

      const apiKey = authHeader.slice(7);
      const keyEntry = lookupApiKey(keysFile, apiKey);
      if (!keyEntry) {
        jsonResponse(res, 403, { error: 'Invalid API key' });
        return;
      }

      const teamId = keyEntry.team_id;
      const teamRunsDir = path.join(dataDir, 'runs', teamId);

      // POST /api/push
      if (url === '/api/push' && method === 'POST') {
        try {
          const body = await readBody(req);
          const parsed = PushRunSchema.safeParse(JSON.parse(body));
          if (!parsed.success) {
            jsonResponse(res, 400, { error: 'Invalid request body', details: parsed.error.issues });
            return;
          }

          const { run_id, signature, findings, attestation, metadata } = parsed.data;

          // Validate run_id format
          if (!/^[\w.:-]+$/.test(run_id)) {
            jsonResponse(res, 400, { error: 'Invalid run_id format' });
            return;
          }

          const runDir = path.join(teamRunsDir, run_id);
          fs.mkdirSync(runDir, { recursive: true });

          fs.writeFileSync(path.join(runDir, 'signature.json'), JSON.stringify(signature, null, 2));
          fs.writeFileSync(path.join(runDir, 'findings.json'), JSON.stringify(findings, null, 2));

          if (attestation) {
            fs.writeFileSync(path.join(runDir, 'attestation.json'), JSON.stringify(attestation, null, 2));
          }
          if (metadata) {
            fs.writeFileSync(path.join(runDir, 'metadata.json'), JSON.stringify(metadata, null, 2));
          }

          jsonResponse(res, 200, { status: 'ok', run_id });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error';
          if (message === 'Request body too large') {
            jsonResponse(res, 413, { error: 'Request body too large (max 1MB)' });
          } else {
            jsonResponse(res, 400, { error: message });
          }
        }
        return;
      }

      // GET /api/runs
      if (url === '/api/runs' && method === 'GET') {
        fs.mkdirSync(teamRunsDir, { recursive: true });
        try {
          const entries = fs.readdirSync(teamRunsDir, { withFileTypes: true });
          const runs = entries
            .filter(e => e.isDirectory())
            .map(e => {
              const sigPath = path.join(teamRunsDir, e.name, 'signature.json');
              const metaPath = path.join(teamRunsDir, e.name, 'metadata.json');
              return {
                run_id: e.name,
                has_signature: fs.existsSync(sigPath),
                has_metadata: fs.existsSync(metaPath),
              };
            })
            .sort((a, b) => b.run_id.localeCompare(a.run_id));

          jsonResponse(res, 200, runs);
        } catch {
          jsonResponse(res, 200, []);
        }
        return;
      }

      // GET /api/runs/:runId
      const runDetailMatch = url.match(/^\/api\/runs\/([^/]+)$/);
      if (runDetailMatch && method === 'GET') {
        const runId = decodeURIComponent(runDetailMatch[1]);
        if (!/^[\w.:-]+$/.test(runId)) {
          jsonResponse(res, 400, { error: 'Invalid run ID' });
          return;
        }

        const runDir = path.join(teamRunsDir, runId);
        const resolved = path.resolve(runDir);
        if (!resolved.startsWith(path.resolve(teamRunsDir) + path.sep)) {
          jsonResponse(res, 400, { error: 'Invalid run ID' });
          return;
        }

        const sigPath = path.join(runDir, 'signature.json');
        const findingsPath = path.join(runDir, 'findings.json');

        if (!fs.existsSync(sigPath)) {
          jsonResponse(res, 404, { error: 'Run not found' });
          return;
        }

        const signature = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
        const findings = fs.existsSync(findingsPath)
          ? JSON.parse(fs.readFileSync(findingsPath, 'utf8'))
          : [];

        jsonResponse(res, 200, { run_id: runId, signature, findings });
        return;
      }

      // DELETE /api/runs/:runId
      if (runDetailMatch && method === 'DELETE') {
        const runId = decodeURIComponent(runDetailMatch[1]);
        if (!/^[\w.:-]+$/.test(runId)) {
          jsonResponse(res, 400, { error: 'Invalid run ID' });
          return;
        }

        const runDir = path.join(teamRunsDir, runId);
        const resolved = path.resolve(runDir);
        if (!resolved.startsWith(path.resolve(teamRunsDir) + path.sep)) {
          jsonResponse(res, 400, { error: 'Invalid run ID' });
          return;
        }

        if (!fs.existsSync(runDir)) {
          jsonResponse(res, 404, { error: 'Run not found' });
          return;
        }

        fs.rmSync(runDir, { recursive: true, force: true });
        jsonResponse(res, 200, { status: 'deleted', run_id: runId });
        return;
      }

      jsonResponse(res, 404, { error: 'Not found' });
      return;
    }

    jsonResponse(res, 404, { error: 'Not found' });
  });

  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`AgentCI Remote Control Plane running at http://localhost:${port}`);
    // eslint-disable-next-line no-console
    console.log(`  Health:  http://localhost:${port}/healthz`);
  });

  return server;
}
