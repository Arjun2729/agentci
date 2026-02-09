import { DiffResult, EffectSignature, PolicyFinding, TraceEvent } from '../core/types';

export interface ReportInput {
  baseline: EffectSignature | null;
  current: EffectSignature;
  diff: DiffResult;
  findings: PolicyFinding[];
  trace?: TraceEvent[];
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderList(
  title: string,
  items: string[],
  options?: { id?: string; evidence?: Record<string, number> }
): string {
  const safeItems = items
    .map((item) => {
      const escaped = escapeHtml(item);
      const evidence = options?.evidence?.[item];
      if (evidence !== undefined) {
        return `<li><a href="#trace-${evidence}">${escaped}</a></li>`;
      }
      return `<li>${escaped}</li>`;
    })
    .join('');
  return `
    <section class="card" ${options?.id ? `id="${options.id}"` : ''}>
      <h3>${escapeHtml(title)}</h3>
      <ul>${safeItems || '<li class="muted">None</li>'}</ul>
    </section>
  `;
}

export function generateReportHtml(input: ReportInput): string {
  // Safely encode data for embedding in a script block — prevent </script> injection
  const data = JSON.stringify(input).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  const summaryClass = input.findings.some((f) => f.severity === 'BLOCK')
    ? 'block'
    : input.findings.some((f) => f.severity === 'WARN')
      ? 'warn'
      : 'pass';

  const traceLines = input.trace ? input.trace.map((t) => JSON.stringify(t)) : [];
  const traceEvidence = (items: string[]): Record<string, number> => {
    const evidence: Record<string, number> = {};
    if (!traceLines.length) return evidence;
    items.forEach((item) => {
      const idx = traceLines.findIndex((line) => line.includes(item));
      if (idx >= 0) evidence[item] = idx;
    });
    return evidence;
  };

  const blastRadius = [
    { label: 'New network egress', count: input.diff.drift.net_hosts.length, anchor: 'drift-net-hosts' },
    { label: 'New files touched', count: input.diff.drift.fs_writes.length, anchor: 'drift-fs-writes' },
    { label: 'New subprocesses', count: input.diff.drift.exec_commands.length, anchor: 'drift-exec-commands' },
    { label: 'New env keys accessed', count: input.diff.drift.sensitive_keys_accessed.length, anchor: 'drift-sensitive' },
  ];

  const topDiffs = Object.entries(input.diff.drift)
    .map(([key, values]) => ({ key, count: values.length }))
    .filter((entry) => entry.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:" />
    <title>AgentCI Report</title>
    <style>
      :root {
        --bg: #f6f4ef;
        --ink: #1e1b16;
        --muted: #6d675f;
        --accent: #1f6feb;
        --card: #ffffff;
        --pass: #1f7a1f;
        --warn: #b97900;
        --block: #b91c1c;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        background: radial-gradient(circle at top left, #fff9e6, transparent 45%), var(--bg);
        color: var(--ink);
      }
      header {
        padding: 24px 32px;
        border-bottom: 1px solid #ddd7cb;
        background: #fffdf8;
      }
      header h1 { margin: 0 0 8px 0; font-size: 22px; }
      header p { margin: 0; color: var(--muted); }
      .container {
        padding: 24px 32px 48px;
        display: grid;
        gap: 20px;
      }
      .summary {
        padding: 14px 18px;
        border-radius: 10px;
        font-weight: 600;
        display: inline-flex;
        align-items: center;
        gap: 8px;
      }
      .summary.pass { background: #e8f7e8; color: var(--pass); }
      .summary.warn { background: #fff3d6; color: var(--warn); }
      .summary.block { background: #ffe0e0; color: var(--block); }
      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 16px;
      }
      .blast {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
      }
      .blast .card {
        text-align: center;
      }
      .blast .count {
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 6px;
      }
      .card {
        background: var(--card);
        padding: 14px 16px;
        border-radius: 12px;
        box-shadow: 0 8px 18px rgba(0,0,0,0.06);
      }
      .card h3 { margin: 0 0 10px; font-size: 15px; }
      ul { margin: 0; padding-left: 18px; }
      li { margin-bottom: 6px; word-break: break-word; }
      .muted { color: var(--muted); }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: 6px 0; border-bottom: 1px solid #eee; font-size: 14px; }
      .trace { max-height: 260px; overflow: auto; font-family: "IBM Plex Mono", monospace; font-size: 12px; }
      .trace-line { display: grid; grid-template-columns: 46px 1fr; gap: 8px; padding: 2px 0; }
      .trace-line .ln { color: var(--muted); text-align: right; }
      .trace-line a { text-decoration: none; color: inherit; }
    </style>
  </head>
  <body>
    <header>
      <h1>AgentCI Report</h1>
      <p>Effect signature drift and policy evaluation.</p>
    </header>
    <div class="container">
      <div class="summary ${summaryClass}">${summaryClass.toUpperCase()}</div>
      <section class="card">
        <h3>Context</h3>
        <table>
          <tr><th>Platform</th><td>${escapeHtml(input.current.meta.platform)}</td></tr>
          <tr><th>Adapter</th><td>${escapeHtml(input.current.meta.adapter)}</td></tr>
          <tr><th>Node</th><td>${escapeHtml(input.current.meta.node_version)}</td></tr>
          <tr><th>Normalization</th><td>${escapeHtml(input.current.meta.normalization_rules_version)}</td></tr>
        </table>
      </section>
      <section class="card">
        <h3>Blast Radius</h3>
        <div class="blast">
          ${blastRadius
            .map(
              (item) =>
                `<div class="card"><div class="count">${item.count}</div><div><a href="#${item.anchor}">${escapeHtml(
                  item.label,
                )}</a></div></div>`,
            )
            .join('')}
        </div>
      </section>
      <section class="card">
        <h3>Top Diffs Since Baseline</h3>
        <ul>
          ${
            topDiffs.length
              ? topDiffs.map((entry) => `<li>${escapeHtml(entry.key)}: ${entry.count}</li>`).join('')
              : '<li class="muted">None</li>'
          }
        </ul>
      </section>
      <section class="card">
        <h3>Policy Findings</h3>
        <ul>
          ${input.findings.length ? input.findings.map((f) => `<li><strong>${escapeHtml(f.severity)}</strong> ${escapeHtml(f.message)}</li>`).join('') : '<li class="muted">None</li>'}
        </ul>
      </section>
      <div class="grid">
        ${renderList('New FS Writes', input.diff.drift.fs_writes, {
          id: 'drift-fs-writes',
          evidence: traceEvidence(input.diff.drift.fs_writes),
        })}
        ${renderList('New FS Deletes', input.diff.drift.fs_deletes, {
          id: 'drift-fs-deletes',
          evidence: traceEvidence(input.diff.drift.fs_deletes),
        })}
        ${renderList('New External Reads', input.diff.drift.fs_reads_external, {
          id: 'drift-fs-reads',
          evidence: traceEvidence(input.diff.drift.fs_reads_external),
        })}
        ${renderList('New Network Hosts', input.diff.drift.net_hosts, {
          id: 'drift-net-hosts',
          evidence: traceEvidence(input.diff.drift.net_hosts),
        })}
        ${renderList('New eTLD+1', input.diff.drift.net_etld_plus_1, {
          id: 'drift-net-etld',
          evidence: traceEvidence(input.diff.drift.net_etld_plus_1),
        })}
        ${renderList('New Exec Commands', input.diff.drift.exec_commands, {
          id: 'drift-exec-commands',
          evidence: traceEvidence(input.diff.drift.exec_commands),
        })}
        ${renderList('New Exec Argv', input.diff.drift.exec_argv, {
          id: 'drift-exec-argv',
          evidence: traceEvidence(input.diff.drift.exec_argv),
        })}
        ${renderList('New Sensitive Access', input.diff.drift.sensitive_keys_accessed, {
          id: 'drift-sensitive',
          evidence: traceEvidence(input.diff.drift.sensitive_keys_accessed),
        })}
      </div>
      ${input.trace && input.trace.length ? `
      <section class="card">
        <h3>Trace Timeline</h3>
        <div class="trace">
          ${traceLines
            .map(
              (line, idx) =>
                `<div class="trace-line" id="trace-${idx}"><div class="ln">${idx + 1}</div><div>${escapeHtml(
                  line,
                )}</div></div>`,
            )
            .join('')}
        </div>
      </section>
      ` : ''}
    </div>
    <script>
      window.__AGENTCI_DATA__ = ${data};
    </script>
  </body>
</html>`;
}
