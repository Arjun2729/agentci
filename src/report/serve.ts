import http from 'http';
import fs from 'fs';
import path from 'path';

function listReports(dir: string): { name: string; fullPath: string; mtime: number }[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const reports: { name: string; fullPath: string; mtime: number }[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const reportPath = path.join(dir, entry.name, 'report.html');
    if (fs.existsSync(reportPath)) {
      const stat = fs.statSync(reportPath);
      reports.push({ name: entry.name, fullPath: reportPath, mtime: stat.mtimeMs });
    }
  }
  return reports.sort((a, b) => b.mtime - a.mtime);
}

function renderIndex(reports: { name: string }[]): string {
  const items = reports
    .map((report) => `<li><a href="/runs/${report.name}/report.html">${report.name}</a></li>`)
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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
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
      res.writeHead(302, { Location: `/runs/${reports[0].name}/report.html` });
      res.end();
      return;
    }
    if (url.startsWith('/runs/')) {
      const relative = path.normalize(url.replace('/runs/', ''));
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
      const filePath = path.join(dir, relative);
      if (!fs.existsSync(filePath)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      const content = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
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
