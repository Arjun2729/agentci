/**
 * AgentCI Dashboard - a hosted web app for viewing signatures,
 * policy findings, and drift trends over time.
 */

import http from 'http';
import fs from 'fs';
import path from 'path';
import { EffectSignature, PolicyFinding } from '../core/types';
import { diffSignatures } from '../core/diff/diff';
import { evaluatePolicy } from '../core/policy/evaluate';
import { loadConfig } from '../core/policy/config';
import { verifyTraceIntegrity } from '../core/integrity';

interface RunSummary {
  runId: string;
  timestamp: number;
  status: 'pass' | 'warn' | 'block';
  findingsCount: number;
  driftCount: number;
  adapter: string;
  platform: string;
  integrityVerified: boolean | null;
}

function discoverRuns(runsDir: string): RunSummary[] {
  if (!fs.existsSync(runsDir)) return [];
  const entries = fs.readdirSync(runsDir, { withFileTypes: true });
  const summaries: RunSummary[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const sigPath = path.join(runsDir, entry.name, 'signature.json');
    if (!fs.existsSync(sigPath)) continue;

    try {
      const sig: EffectSignature = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
      const configPath = path.join(path.dirname(runsDir), 'config.yaml');
      const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
      const findings = evaluatePolicy(sig, config);

      const hasBlock = findings.some((f) => f.severity === 'BLOCK');
      const hasWarn = findings.some((f) => f.severity === 'WARN');

      const tracePath = path.join(runsDir, entry.name, 'trace.jsonl');
      let integrityVerified: boolean | null = null;
      if (fs.existsSync(tracePath)) {
        try {
          const result = verifyTraceIntegrity(tracePath, entry.name);
          integrityVerified = result.valid;
        } catch {
          integrityVerified = null;
        }
      }

      const parts = entry.name.split('-');
      const ts = parseInt(parts[0], 10) || 0;

      summaries.push({
        runId: entry.name,
        timestamp: ts,
        status: hasBlock ? 'block' : hasWarn ? 'warn' : 'pass',
        findingsCount: findings.length,
        driftCount: 0,
        adapter: sig.meta.adapter,
        platform: sig.meta.platform,
        integrityVerified,
      });
    } catch {
      // skip invalid runs
    }
  }

  return summaries.sort((a, b) => b.timestamp - a.timestamp);
}

function getRunDetail(runsDir: string, runId: string): {
  signature: EffectSignature;
  findings: PolicyFinding[];
  integrity: { valid: boolean; details: string } | null;
} | null {
  const sigPath = path.join(runsDir, runId, 'signature.json');
  if (!fs.existsSync(sigPath)) return null;

  const sig: EffectSignature = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
  const configPath = path.join(path.dirname(runsDir), 'config.yaml');
  const config = loadConfig(fs.existsSync(configPath) ? configPath : undefined, process.cwd());
  const findings = evaluatePolicy(sig, config);

  const tracePath = path.join(runsDir, runId, 'trace.jsonl');
  let integrity: { valid: boolean; details: string } | null = null;
  if (fs.existsSync(tracePath)) {
    try {
      integrity = verifyTraceIntegrity(tracePath, runId);
    } catch {
      integrity = null;
    }
  }

  return { signature: sig, findings, integrity };
}

function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AgentCI Dashboard</title>
  <style>
    :root {
      --bg: #f6f4ef; --ink: #1e1b16; --muted: #6d675f;
      --card: #ffffff; --pass: #1f7a1f; --warn: #b97900; --block: #b91c1c;
      --border: #ddd7cb; --accent: #1f6feb;
    }
    * { box-sizing: border-box; margin: 0; }
    body { font-family: "IBM Plex Sans","Segoe UI",system-ui,sans-serif; background: var(--bg); color: var(--ink); }
    header { padding: 20px 32px; border-bottom: 1px solid var(--border); background: #fffdf8; display: flex; justify-content: space-between; align-items: center; }
    header h1 { font-size: 20px; }
    header .subtitle { color: var(--muted); font-size: 14px; }
    .container { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: var(--card); padding: 16px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .stat-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
    .stat-card .value.pass { color: var(--pass); }
    .stat-card .value.warn { color: var(--warn); }
    .stat-card .value.block { color: var(--block); }
    table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    th { text-align: left; padding: 12px 16px; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid var(--border); }
    td { padding: 12px 16px; border-bottom: 1px solid #f0ece5; font-size: 14px; }
    tr:hover td { background: #faf8f3; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
    .badge.pass { background: #e8f7e8; color: var(--pass); }
    .badge.warn { background: #fff3d6; color: var(--warn); }
    .badge.block { background: #ffe0e0; color: var(--block); }
    .integrity { font-size: 12px; }
    .integrity.verified { color: var(--pass); }
    .integrity.failed { color: var(--block); }
    .integrity.unknown { color: var(--muted); }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .trend { margin-top: 24px; }
    .trend h2 { font-size: 16px; margin-bottom: 12px; }
    .bar-chart { display: flex; align-items: flex-end; gap: 4px; height: 120px; background: var(--card); padding: 16px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .bar { flex: 1; min-width: 8px; max-width: 24px; border-radius: 4px 4px 0 0; cursor: pointer; position: relative; }
    .bar.pass { background: var(--pass); }
    .bar.warn { background: var(--warn); }
    .bar.block { background: var(--block); }
    .bar:hover::after { content: attr(data-label); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: var(--ink); color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; white-space: nowrap; }
    .empty { text-align: center; padding: 48px; color: var(--muted); }
    #detail-modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.4); z-index: 100; }
    #detail-modal .modal-content { background: var(--card); max-width: 700px; margin: 60px auto; border-radius: 12px; padding: 24px; max-height: 80vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
    #detail-modal .close-btn { float: right; cursor: pointer; font-size: 20px; color: var(--muted); border: none; background: none; }
    #detail-modal h2 { font-size: 18px; margin-bottom: 16px; }
    #detail-modal pre { background: #f0ece5; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; }
    #detail-modal .finding { padding: 8px 0; border-bottom: 1px solid #f0ece5; font-size: 13px; }
    #detail-modal .finding:last-child { border-bottom: none; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>AgentCI Dashboard</h1>
      <div class="subtitle">Effect signature monitoring and policy compliance</div>
    </div>
    <div class="subtitle" id="last-updated"></div>
  </header>
  <div class="container">
    <div class="stats" id="stats"></div>
    <div class="trend" id="trend-section" style="display:none">
      <h2>Run History</h2>
      <div class="bar-chart" id="bar-chart"></div>
    </div>
    <div style="margin-top: 24px">
      <table id="runs-table" style="display:none">
        <thead>
          <tr>
            <th>Run ID</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Adapter</th>
            <th>Platform</th>
            <th>Integrity</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody id="runs-body"></tbody>
      </table>
      <div class="empty" id="empty-state">No runs found. Record an agent run and summarize it to see data here.</div>
    </div>
  </div>
  <div id="detail-modal">
    <div class="modal-content">
      <button class="close-btn" onclick="closeModal()">&times;</button>
      <div id="modal-body"></div>
    </div>
  </div>
  <script>
    let runs = [];
    async function load() {
      const res = await fetch('/api/runs');
      runs = await res.json();
      render();
    }
    function render() {
      const total = runs.length;
      const pass = runs.filter(r => r.status === 'pass').length;
      const warn = runs.filter(r => r.status === 'warn').length;
      const block = runs.filter(r => r.status === 'block').length;
      document.getElementById('stats').innerHTML =
        '<div class="stat-card"><div class="label">Total Runs</div><div class="value">' + total + '</div></div>' +
        '<div class="stat-card"><div class="label">Passing</div><div class="value pass">' + pass + '</div></div>' +
        '<div class="stat-card"><div class="label">Warnings</div><div class="value warn">' + warn + '</div></div>' +
        '<div class="stat-card"><div class="label">Blocked</div><div class="value block">' + block + '</div></div>';
      if (!total) { document.getElementById('empty-state').style.display = 'block'; return; }
      document.getElementById('empty-state').style.display = 'none';
      document.getElementById('runs-table').style.display = 'table';
      const tbody = document.getElementById('runs-body');
      tbody.innerHTML = runs.map(r => {
        const intClass = r.integrityVerified === true ? 'verified' : r.integrityVerified === false ? 'failed' : 'unknown';
        const intLabel = r.integrityVerified === true ? 'Verified' : r.integrityVerified === false ? 'Failed' : 'N/A';
        const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '-';
        return '<tr onclick="showDetail(\\'' + r.runId + '\\')" style="cursor:pointer">' +
          '<td><a href="#">' + r.runId + '</a></td>' +
          '<td><span class="badge ' + r.status + '">' + r.status + '</span></td>' +
          '<td>' + r.findingsCount + '</td>' +
          '<td>' + r.adapter + '</td>' +
          '<td>' + r.platform + '</td>' +
          '<td><span class="integrity ' + intClass + '">' + intLabel + '</span></td>' +
          '<td>' + ts + '</td></tr>';
      }).join('');
      // Trend chart
      const recent = runs.slice(0, 50).reverse();
      if (recent.length > 1) {
        document.getElementById('trend-section').style.display = 'block';
        const maxFindings = Math.max(1, ...recent.map(r => r.findingsCount));
        document.getElementById('bar-chart').innerHTML = recent.map(r => {
          const h = Math.max(8, (r.findingsCount / maxFindings) * 100);
          return '<div class="bar ' + r.status + '" style="height:' + h + '%" data-label="' + r.runId.slice(0,12) + ': ' + r.findingsCount + ' findings"></div>';
        }).join('');
      }
      document.getElementById('last-updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    }
    async function showDetail(runId) {
      const res = await fetch('/api/runs/' + runId);
      const data = await res.json();
      const modal = document.getElementById('detail-modal');
      const body = document.getElementById('modal-body');
      let html = '<h2>Run: ' + runId + '</h2>';
      if (data.integrity) {
        const ic = data.integrity.valid ? 'verified' : 'failed';
        html += '<p class="integrity ' + ic + '">Integrity: ' + data.integrity.details + '</p>';
      }
      html += '<h3 style="margin-top:16px">Effects</h3>';
      html += '<pre>' + JSON.stringify(data.signature.effects, null, 2) + '</pre>';
      if (data.findings.length) {
        html += '<h3 style="margin-top:16px">Policy Findings (' + data.findings.length + ')</h3>';
        html += data.findings.map(f => '<div class="finding"><span class="badge ' + f.severity.toLowerCase() + '">' + f.severity + '</span> ' + f.message + '</div>').join('');
      } else {
        html += '<p style="margin-top:16px;color:var(--pass)">No policy violations.</p>';
      }
      body.innerHTML = html;
      modal.style.display = 'block';
    }
    function closeModal() { document.getElementById('detail-modal').style.display = 'none'; }
    document.getElementById('detail-modal').addEventListener('click', function(e) { if (e.target === this) closeModal(); });
    load();
    setInterval(load, 15000);
  </script>
</body>
</html>`;
}

export function serveDashboard(runsDir: string, port: number): void {
  const server = http.createServer((req, res) => {
    const url = req.url || '/';

    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(dashboardHtml());
      return;
    }

    if (url === '/api/runs') {
      const runs = discoverRuns(runsDir);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(runs));
      return;
    }

    if (url.startsWith('/api/runs/')) {
      const runId = url.replace('/api/runs/', '').replace(/\/$/, '');
      if (runId.includes('..') || runId.includes('/')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid run ID' }));
        return;
      }
      const detail = getRunDetail(runsDir, runId);
      if (!detail) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Run not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(detail));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`AgentCI Dashboard running at http://localhost:${port}`);
  });
}
