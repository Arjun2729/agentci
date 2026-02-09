# AgentCI GitHub Action

Runs AgentCI in CI, posts a short PR comment, and uploads the HTML report as an artifact.

## Usage

```yaml
- name: AgentCI
  uses: ./github-action
  with:
    command: "node my_agent.js"
    baseline: .agentci/baseline.json
    config: .agentci/config.yaml
    token: ${{ secrets.GITHUB_TOKEN }}
```

Inputs:
- `command` (required): command to run under the recorder
- `baseline`: path to baseline signature (default `.agentci/baseline.json`)
- `config`: path to config.yaml (default `.agentci/config.yaml`)
- `comment`: `true|false` (default `true`)
- `report`: `true|false` (default `true`)
- `token`: GitHub token for PR comments
