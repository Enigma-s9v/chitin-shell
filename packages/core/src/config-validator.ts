/**
 * Configuration Validator — Pre-flight checks before Shell starts.
 *
 * Validates ChitinShellOptions comprehensively so startup fails fast
 * with clear error messages rather than cryptic runtime errors.
 */

import type { ChitinShellOptions } from './shell.js';
import type { PolicyConfig } from './policy/types.js';

export interface ConfigValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/** Validate ChitinShellOptions before creating the Shell */
export function validateShellConfig(options: ChitinShellOptions): ConfigValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Policy validation
  if (typeof options.policy === 'string') {
    // Path-based policy: check extension
    if (!options.policy.endsWith('.json')) {
      warnings.push(`Policy file '${options.policy}' does not have .json extension`);
    }
  } else if (options.policy !== undefined) {
    // Inline policy object
    validatePolicyConfig(options.policy, errors, warnings);
  }

  // On-chain config validation
  if (options.onChain) {
    if (!options.onChain.rpcUrl) {
      errors.push('On-chain config: rpcUrl is required');
    } else if (!isValidUrl(options.onChain.rpcUrl)) {
      errors.push(`On-chain config: rpcUrl '${options.onChain.rpcUrl}' is not a valid URL`);
    }

    if (!options.onChain.contractAddress) {
      errors.push('On-chain config: contractAddress is required');
    } else if (!isValidAddress(options.onChain.contractAddress)) {
      errors.push(`On-chain config: contractAddress '${options.onChain.contractAddress}' is not a valid Ethereum address`);
    }
  }

  // DID resolver config validation
  if (options.didResolver) {
    if (options.didResolver.chainId !== undefined) {
      if (typeof options.didResolver.chainId !== 'number' || options.didResolver.chainId <= 0) {
        errors.push(`DID resolver: chainId must be a positive number, got '${options.didResolver.chainId}'`);
      }
    }
  }

  // ZKP config validation
  if (options.zkp) {
    if (typeof options.zkp.enabled !== 'boolean') {
      errors.push('ZKP config: enabled must be a boolean');
    }
    if (options.zkp.provenance !== undefined && typeof options.zkp.provenance !== 'boolean') {
      errors.push('ZKP config: provenance must be a boolean');
    }
    if (options.zkp.nonLeakage !== undefined && typeof options.zkp.nonLeakage !== 'boolean') {
      errors.push('ZKP config: nonLeakage must be a boolean');
    }
    if (options.zkp.skillSafety !== undefined && typeof options.zkp.skillSafety !== 'boolean') {
      errors.push('ZKP config: skillSafety must be a boolean');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

function validatePolicyConfig(policy: PolicyConfig, errors: string[], warnings: string[]): void {
  if (!policy.tiers) {
    errors.push('Policy config: tiers object is required');
    return;
  }

  const tierKeys = ['tier_0', 'tier_1', 'tier_2', 'tier_3'] as const;
  for (const key of tierKeys) {
    const tier = policy.tiers[key];
    if (!tier) {
      warnings.push(`Policy config: ${key} is not defined`);
      continue;
    }

    if (!tier.description) {
      warnings.push(`Policy config: ${key}.description is empty`);
    }

    if (tier.constraints?.rate_limit) {
      const rl = tier.constraints.rate_limit;
      if (typeof rl.max !== 'number' || rl.max <= 0) {
        errors.push(`Policy config: ${key}.constraints.rate_limit.max must be a positive number`);
      }
      if (!rl.window || typeof rl.window !== 'string') {
        errors.push(`Policy config: ${key}.constraints.rate_limit.window is required`);
      }
    }
  }

  // Rate limits validation
  if (policy.rate_limits) {
    for (const [action, rule] of Object.entries(policy.rate_limits)) {
      if (typeof rule.max !== 'number' || rule.max <= 0) {
        errors.push(`Policy config: rate_limits.${action}.max must be a positive number`);
      }
    }
  }
}

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}
