/**
 * Policy Engine — Type Definitions
 *
 * Policies are deterministic rules (no LLM) that gate what Intents are approved.
 * Stored as JSON locally or on-chain for immutability.
 */

import type { ActionType, SecurityTier } from '../intent/types.js';

/** Rate limit rule for an action */
export interface RateLimitRule {
  /** Maximum number of actions allowed */
  max: number;
  /** Time window: '1m', '1h', '24h' */
  window: string;
}

/** Configuration for a single security tier */
export interface TierConfig {
  description: string;
  actions: ActionType[];
  verification: 'none' | 'local' | 'on_chain' | 'human_approval';
  constraints?: {
    recipient_whitelist?: boolean;
    rate_limit?: RateLimitRule;
    [key: string]: unknown;
  };
  multisig?: {
    required: number;
    timeout: string;
  };
}

/** Full policy configuration */
export interface PolicyConfig {
  version: string;
  tiers: {
    tier_0: TierConfig;
    tier_1: TierConfig;
    tier_2: TierConfig;
    tier_3: TierConfig;
  };
  rate_limits?: Record<string, RateLimitRule>;
  whitelists?: {
    contacts?: string[];
    domains?: string[];
    actions?: ActionType[];
  };
  blacklists?: {
    contacts?: string[];
    domains?: string[];
  };
}

/** Result of policy verification */
export interface VerificationResult {
  approved: boolean;
  tier: SecurityTier;
  reason: string;
  approval_token?: string;
  requires_human?: boolean;
}

/** Sliding window entry for rate limiting */
export interface RateLimitEntry {
  agent_did: string;
  action_type: string;
  timestamps: number[];
}
