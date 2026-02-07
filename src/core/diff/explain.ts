import { PolicyFinding } from '../types';

export function summarizeFindings(findings: PolicyFinding[]): {
  hasBlock: boolean;
  hasWarn: boolean;
} {
  return {
    hasBlock: findings.some((f) => f.severity === 'BLOCK'),
    hasWarn: findings.some((f) => f.severity === 'WARN')
  };
}

export function formatFinding(finding: PolicyFinding): string {
  if (finding.suggestion) {
    return `${finding.message} Suggestion: ${finding.suggestion}`;
  }
  return finding.message;
}
