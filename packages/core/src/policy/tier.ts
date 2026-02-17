import type { SecurityTier } from '../intent/types.js';
import type { PolicyConfig } from './types.js';

const TIER_KEYS = ['tier_0', 'tier_1', 'tier_2', 'tier_3'] as const;

export function determineTier(actionType: string, policy: PolicyConfig): SecurityTier {
  for (const key of TIER_KEYS) {
    const tier = policy.tiers[key];
    if (tier.actions.includes(actionType)) {
      return Number(key.charAt(5)) as SecurityTier;
    }
  }
  // Fail safe: unknown actions default to highest security tier
  return 3;
}
