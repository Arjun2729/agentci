/**
 * Structured debug logger for AgentCI recorder.
 *
 * Enable with AGENTCI_DEBUG=1 to write to stderr.
 */

const ENABLED = !!process.env.AGENTCI_DEBUG;

function timestamp(): string {
  return new Date().toISOString();
}

function write(level: string, component: string, message: string, extra?: Record<string, unknown>): void {
  if (!ENABLED) return;
  const parts = [`[agentci ${level}] [${component}]`, message];
  if (extra) {
    parts.push(JSON.stringify(extra));
  }
  process.stderr.write(parts.join(' ') + '\n');
}

export const logger = {
  debug(component: string, message: string, extra?: Record<string, unknown>): void {
    write('DEBUG', component, message, extra);
  },
  warn(component: string, message: string, extra?: Record<string, unknown>): void {
    write('WARN', component, message, extra);
  },
  error(component: string, message: string, extra?: Record<string, unknown>): void {
    write('ERROR', component, message, extra);
  },
  enabled: ENABLED,
};
