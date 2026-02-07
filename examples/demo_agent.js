const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const variant = process.env.DEMO_VARIANT || '1';
const workspaceDir = path.join(process.cwd(), 'workspace');
fs.mkdirSync(workspaceDir, { recursive: true });

const targetFile = path.join(workspaceDir, variant === '1' ? 'demo.txt' : 'demo-variant.txt');
fs.writeFileSync(targetFile, `hello from variant ${variant}\n`);

https.get('https://example.com', (res) => {
  res.on('data', () => {});
  res.on('end', () => {
    // noop
  });
}).on('error', () => {
  // ignore demo network errors
});

execSync('echo "demo run"');
