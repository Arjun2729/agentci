/**
 * Zod schemas for validating PolicyConfig, TraceEvent, and EffectSignature.
 */

import { z } from 'zod';

export const PolicyConfigSchema = z.object({
  version: z.number(),
  workspace_root: z.string(),
  policy: z.object({
    filesystem: z.object({
      allow_writes: z.array(z.string()),
      block_writes: z.array(z.string()),
    }),
    network: z.object({
      allow_etld_plus_1: z.array(z.string()),
      allow_hosts: z.array(z.string()),
    }),
    exec: z.object({
      allow_commands: z.array(z.string()),
      block_commands: z.array(z.string()),
    }),
    sensitive: z.object({
      block_env: z.array(z.string()),
      block_file_globs: z.array(z.string()),
    }),
  }),
  reporting: z
    .object({
      explain_templates: z.boolean().optional(),
    })
    .optional(),
});

export const TraceEventSchema = z.object({
  id: z.string(),
  timestamp: z.number(),
  run_id: z.string(),
  type: z.enum(['lifecycle', 'tool_call', 'tool_result', 'effect']),
  data: z.unknown(),
  metadata: z.record(z.unknown()).optional(),
});

export const EffectSignatureSchema = z.object({
  meta: z.object({
    signature_version: z.literal('1.0'),
    agentci_version: z.string(),
    platform: z.string(),
    adapter: z.enum(['node-hook', 'openclaw+node-hook']),
    scenario_id: z.string(),
    node_version: z.string(),
  }),
  effects: z.object({
    fs_writes: z.array(z.string()),
    fs_reads_external: z.array(z.string()),
    fs_deletes: z.array(z.string()),
    net_etld_plus_1: z.array(z.string()),
    net_hosts: z.array(z.string()),
    exec_commands: z.array(z.string()),
    exec_argv: z.array(z.string()),
    sensitive_keys_accessed: z.array(z.string()),
  }),
});

export type ValidatedPolicyConfig = z.infer<typeof PolicyConfigSchema>;
export type ValidatedTraceEvent = z.infer<typeof TraceEventSchema>;
export type ValidatedEffectSignature = z.infer<typeof EffectSignatureSchema>;

/**
 * Validate a PolicyConfig, returning the parsed config or throwing with details.
 */
export function validatePolicyConfig(raw: unknown): ValidatedPolicyConfig {
  return PolicyConfigSchema.parse(raw);
}

/**
 * Safely validate a PolicyConfig, returning null on failure with logged errors.
 */
export function safeParsePolicyConfig(raw: unknown): { success: true; data: ValidatedPolicyConfig } | { success: false; errors: string[] } {
  const result = PolicyConfigSchema.safeParse(raw);
  if (result.success) {
    return { success: true, data: result.data };
  }
  const errors = result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
  return { success: false, errors };
}

/**
 * Validate a single TraceEvent.
 */
export function validateTraceEvent(raw: unknown): ValidatedTraceEvent {
  return TraceEventSchema.parse(raw);
}

/**
 * Validate an EffectSignature.
 */
export function validateEffectSignature(raw: unknown): ValidatedEffectSignature {
  return EffectSignatureSchema.parse(raw);
}
