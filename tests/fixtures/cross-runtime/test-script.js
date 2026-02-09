/* eslint-disable no-undef, no-unused-vars */
// Cross-runtime test script for Node.js
// Performs: write file, read file, spawn subprocess, access env var
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const outDir = process.env.AGENTCI_TEST_OUT || path.join(__dirname, 'out');
fs.mkdirSync(outDir, { recursive: true });

// 1. Write a file
fs.writeFileSync(path.join(outDir, 'hello.txt'), 'hello from node');

// 2. Read a file
fs.readFileSync(path.join(outDir, 'hello.txt'), 'utf-8');

// 3. Spawn subprocess
execSync('echo cross-runtime-test');

// 4. Access env var
const _ = process.env.HOME;
