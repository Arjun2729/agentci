#!/usr/bin/env bash
set -euo pipefail

npm run build

node dist/cli/main.js adopt

node dist/cli/main.js record -- node examples/demo_agent.js
LATEST_RUN=$(ls -1t .agentci/runs | head -n 1)
node dist/cli/main.js summarize ".agentci/runs/${LATEST_RUN}/trace.jsonl"

if [ ! -f .agentci/baseline.json ]; then
  cp ".agentci/runs/${LATEST_RUN}/signature.json" .agentci/baseline.json
fi

DEMO_VARIANT=2 node dist/cli/main.js record -- node examples/demo_agent.js
LATEST_RUN=$(ls -1t .agentci/runs | head -n 1)
node dist/cli/main.js summarize ".agentci/runs/${LATEST_RUN}/trace.jsonl"

set +e
node dist/cli/main.js diff .agentci/baseline.json ".agentci/runs/${LATEST_RUN}/signature.json"
set -e

node dist/cli/main.js report .agentci/baseline.json ".agentci/runs/${LATEST_RUN}/signature.json" --trace ".agentci/runs/${LATEST_RUN}/trace.jsonl"

node dist/cli/main.js serve --dir .agentci/runs --port 8787 &
SERVER_PID=$!

sleep 2
kill ${SERVER_PID} >/dev/null 2>&1 || true

printf "\nDemo complete. Report served briefly at http://localhost:8787\n"
