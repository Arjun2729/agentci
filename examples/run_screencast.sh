#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# AgentCI Screencast Demo
#
# Shows the full workflow:
#   1. Set up a policy
#   2. Record a "safe" agent → establish baseline
#   3. Record a "rogue" agent → catch violations via diff
#   4. Generate an HTML report
#
# Usage:
#   npm run build && bash examples/run_screencast.sh
#
# Tip: Use `asciinema rec` or similar to capture this as a GIF/video.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

CLI="node dist/cli/main.js"
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

step() {
  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}$1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  sleep 1
}

# Clean up any previous demo state
rm -rf .agentci workspace .env.backup 2>/dev/null || true

# ──────────────────────────────────────────────────────────────
step "Step 1: Set up a policy for this repository"
echo -e "$ ${GREEN}agentci adopt${NC}"
$CLI adopt
echo ""
echo "Created .agentci/config.yaml with default security policy."

# ──────────────────────────────────────────────────────────────
step "Step 2: Record a well-behaved agent"
echo -e "$ ${GREEN}agentci record -- node examples/demo_agent_safe.js${NC}"
$CLI record -- node examples/demo_agent_safe.js
SAFE_RUN=$(ls -1t .agentci/runs | head -n 1)
echo ""
echo -e "Run ID: ${YELLOW}${SAFE_RUN}${NC}"
echo ""

echo -e "$ ${GREEN}agentci summarize .agentci/runs/${SAFE_RUN}/trace.jsonl${NC}"
$CLI summarize ".agentci/runs/${SAFE_RUN}/trace.jsonl"
echo ""
echo "Effect Signature written. Setting as baseline..."
cp ".agentci/runs/${SAFE_RUN}/signature.json" .agentci/baseline.json
echo -e "${GREEN}Baseline saved.${NC}"

# ──────────────────────────────────────────────────────────────
step "Step 3: Record a rogue agent (same task, different behavior)"
echo -e "$ ${GREEN}agentci record -- node examples/demo_agent_rogue.js${NC}"
$CLI record -- node examples/demo_agent_rogue.js
ROGUE_RUN=$(ls -1t .agentci/runs | head -n 1)
echo ""
echo -e "Run ID: ${YELLOW}${ROGUE_RUN}${NC}"
echo ""

echo -e "$ ${GREEN}agentci summarize .agentci/runs/${ROGUE_RUN}/trace.jsonl${NC}"
$CLI summarize ".agentci/runs/${ROGUE_RUN}/trace.jsonl"

# ──────────────────────────────────────────────────────────────
step "Step 4: Diff against baseline — catch the violations"
echo -e "$ ${GREEN}agentci diff .agentci/baseline.json .agentci/runs/${ROGUE_RUN}/signature.json${NC}"
echo ""
set +e
$CLI diff .agentci/baseline.json ".agentci/runs/${ROGUE_RUN}/signature.json"
EXIT_CODE=$?
set -e
echo ""
if [ $EXIT_CODE -ne 0 ]; then
  echo -e "${RED}Exit code: ${EXIT_CODE} — policy violation detected.${NC}"
  echo -e "${RED}In CI, this would fail the build.${NC}"
else
  echo -e "${GREEN}Exit code: 0 — no violations.${NC}"
fi

# ──────────────────────────────────────────────────────────────
step "Step 5: Generate an HTML report"
echo -e "$ ${GREEN}agentci report .agentci/baseline.json .agentci/runs/${ROGUE_RUN}/signature.json --trace .agentci/runs/${ROGUE_RUN}/trace.jsonl${NC}"
$CLI report .agentci/baseline.json ".agentci/runs/${ROGUE_RUN}/signature.json" --trace ".agentci/runs/${ROGUE_RUN}/trace.jsonl"

# ──────────────────────────────────────────────────────────────
step "Step 6: Verify trace integrity"
echo -e "$ ${GREEN}agentci verify .agentci/runs/${ROGUE_RUN}${NC}"
$CLI verify ".agentci/runs/${ROGUE_RUN}"

# ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}Demo complete.${NC}"
echo ""
echo "The rogue agent:"
echo "  - Wrote a file outside the workspace (.env.backup)"
echo "  - Contacted an unknown host (evil-exfil-server.com)"
echo "  - Ran a blocked command (curl)"
echo "  - Accessed a sensitive env var (AWS_SECRET_ACCESS_KEY)"
echo ""
echo "AgentCI caught all of it."
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Clean up demo artifacts
rm -f .env.backup 2>/dev/null || true
