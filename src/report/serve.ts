import http from 'http';
import fs from 'fs';
import path from 'path';

const CSP_HEADER =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:";

const ALLOWED_EXTENSIONS = new Set(['.html', '.json']);

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function isValidRunName(dir: string, name: string): boolean {
  if (!/^[\w.:-]+$/.test(name)) return false;
  const resolved = path.resolve(dir, name);
  return resolved.startsWith(path.resolve(dir) + path.sep);
}

function isSafeServePath(baseDir: string, filePath: string): boolean {
  const resolvedBase = path.resolve(baseDir);
  const resolvedFile = path.resolve(filePath);
  if (!resolvedFile.startsWith(resolvedBase + path.sep)) return false;
  const ext = path.extname(resolvedFile);
  if (!ALLOWED_EXTENSIONS.has(ext)) return false;
  // Reject symlinks to prevent escape
  try {
    const stat = fs.lstatSync(resolvedFile);
    if (stat.isSymbolicLink()) return false;
  } catch {
    return false;
  }
  return true;
}

function listReports(dir: string): { name: string; fullPath: string; mtime: number }[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const reports: { name: string; fullPath: string; mtime: number }[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (!isValidRunName(dir, entry.name)) continue;
    const reportPath = path.join(dir, entry.name, 'report.html');
    if (!fs.existsSync(reportPath)) continue;
    try {
      const stat = fs.statSync(reportPath);
      reports.push({ name: entry.name, fullPath: reportPath, mtime: stat.mtimeMs });
    } catch {
      // skip inaccessible entries
    }
  }
  return reports.sort((a, b) => b.mtime - a.mtime);
}

function renderIndex(reports: { name: string }[]): string {
  const items = reports
    .map((report) => `<li><a href="/runs/${escapeHtml(report.name)}/report.html">${escapeHtml(report.name)}</a></li>`)
    .join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AgentCI Reports</title>
  <style>
    body { font-family: "IBM Plex Sans", sans-serif; padding: 24px; background: #f6f4ef; }
    h1 { margin-top: 0; }
  </style>
</head>
<body>
  <h1>AgentCI Reports</h1>
  <p><a href="/latest">Open latest report</a></p>
  <ul>${items || '<li>No reports found.</li>'}</ul>
</body>
</html>`;
}

export function serveReports(dir: string, port: number): void {
  const server = http.createServer((req, res) => {
    const url = req.url || '/';
    if (url === '/' || url === '/index.html') {
      const reports = listReports(dir);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': CSP_HEADER,
      });
      res.end(renderIndex(reports));
      return;
    }
    if (url === '/latest') {
      const reports = listReports(dir);
      if (!reports.length) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('No reports found.');
        return;
      }
      res.writeHead(302, { Location: `/runs/${encodeURIComponent(reports[0].name)}/report.html` });
      res.end();
      return;
    }
    if (url.startsWith('/runs/')) {
      const relative = decodeURIComponent(url.replace('/runs/', ''));
      const filePath = path.join(dir, relative);
      if (!isSafeServePath(dir, filePath)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
      if (!fs.existsSync(filePath)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      const content = fs.readFileSync(filePath);
      const ext = path.extname(filePath);
      const contentType = ext === '.json' ? 'application/json' : 'text/html; charset=utf-8';
      const headers: Record<string, string> = { 'Content-Type': contentType };
      if (ext === '.html') {
        headers['Content-Security-Policy'] = CSP_HEADER;
      }
      res.writeHead(200, headers);
      res.end(content);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  });

  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`AgentCI report server running at http://localhost:${port}`);
  });
}
