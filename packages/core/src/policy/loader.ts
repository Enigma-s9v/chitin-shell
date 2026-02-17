import { readFile } from 'node:fs/promises';
import type { PolicyConfig } from './types.js';

export async function loadPolicyFromFile(filePath: string): Promise<PolicyConfig> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf-8');
  } catch (err) {
    throw new Error(`Failed to read policy file '${filePath}': ${(err as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Policy file '${filePath}' contains invalid JSON`);
  }

  return validatePolicy(parsed, filePath);
}

export function loadDefaultPolicy(): PolicyConfig {
  return {
    version: '1.0',
    tiers: {
      tier_0: {
        description: 'Read-only and internal operations',
        actions: ['think', 'recall', 'summarize', 'read_file', 'read_email'],
        verification: 'none',
      },
      tier_1: {
        description: 'Low-risk write operations to whitelisted targets',
        actions: ['send_message', 'reply_email', 'post_channel'],
        verification: 'local',
        constraints: {
          recipient_whitelist: true,
          rate_limit: { max: 10, window: '1m' },
        },
      },
      tier_2: {
        description: 'Higher-risk operations requiring on-chain verification',
        actions: ['send_email_new', 'file_write', 'api_call', 'create_issue'],
        verification: 'on_chain',
        constraints: {
          rate_limit: { max: 5, window: '1h' },
        },
      },
      tier_3: {
        description: 'Critical operations requiring human approval',
        actions: ['transfer_funds', 'change_permissions', 'bulk_export', 'system_config'],
        verification: 'human_approval',
        multisig: {
          required: 2,
          timeout: '24h',
        },
      },
    },
    whitelists: {
      contacts: [],
      domains: [],
      actions: [],
    },
    blacklists: {
      contacts: [],
      domains: [],
    },
  };
}

const REQUIRED_TIERS = ['tier_0', 'tier_1', 'tier_2', 'tier_3'] as const;

function validatePolicy(data: unknown, source: string): PolicyConfig {
  if (!data || typeof data !== 'object') {
    throw new Error(`Policy from '${source}' must be a JSON object`);
  }

  const obj = data as Record<string, unknown>;

  if (!obj.version || typeof obj.version !== 'string') {
    throw new Error(`Policy from '${source}' is missing required 'version' field`);
  }

  if (!obj.tiers || typeof obj.tiers !== 'object') {
    throw new Error(`Policy from '${source}' is missing required 'tiers' object`);
  }

  const tiers = obj.tiers as Record<string, unknown>;
  for (const tierKey of REQUIRED_TIERS) {
    if (!tiers[tierKey] || typeof tiers[tierKey] !== 'object') {
      throw new Error(`Policy from '${source}' is missing required tier '${tierKey}'`);
    }
  }

  return data as PolicyConfig;
}
