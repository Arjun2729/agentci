/**
 * "Safe" demo agent — stays within policy.
 * Writes files to workspace, hits an allowed API, runs allowed commands.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

const workspaceDir = path.join(process.cwd(), 'workspace');
fs.mkdirSync(workspaceDir, { recursive: true });

// Write some source files
fs.writeFileSync(path.join(workspaceDir, 'index.ts'), `
export function greet(name: string): string {
  return \`Hello, \${name}!\`;
}
`);

fs.writeFileSync(path.join(workspaceDir, 'utils.ts'), `
export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
`);

fs.writeFileSync(path.join(workspaceDir, 'package.json'), JSON.stringify({
  name: 'demo-output',
  version: '1.0.0',
  main: 'index.ts'
}, null, 2));

// Make an allowed network request
https.get('https://example.com', (res) => {
  res.on('data', () => {});
  res.on('end', () => {});
}).on('error', () => {});

// Run an allowed command
const child = spawn('echo', ['build complete']);
child.on('close', () => process.exit(0));
setTimeout(() => process.exit(0), 2000);
