/**
 * Trust Delegation — Scope Operations
 *
 * Utilities for comparing, intersecting, and validating delegation scopes.
 * Scope narrowing ensures that each level of delegation can only reduce
 * permissions, never increase them.
 */

import type { ActionType, SecurityTier } from '../intent/types.js';
import type { DelegationScope } from './types.js';

/**
 * Compute the intersection of two scopes (for chain verification).
 * Returns null if the child requests actions not present in the parent
 * (i.e. the scopes are incompatible).
 */
export function intersectScopes(
  parent: DelegationScope,
  child: DelegationScope,
): DelegationScope | null {
  // Child actions must all exist in parent
  const parentActions = new Set(parent.actions);
  const commonActions: ActionType[] = [];
  for (const action of child.actions) {
    if (!parentActions.has(action)) {
      return null; // child requests an action not in parent
    }
    commonActions.push(action);
  }

  if (commonActions.length === 0) {
    return null;
  }

  // maxTier: take the minimum (more restrictive)
  const maxTier = Math.min(parent.maxTier, child.maxTier) as SecurityTier;

  // maxDepth: take minimum, decremented by 1 (each delegation level costs 1)
  const maxDepth = Math.max(0, Math.min(parent.maxDepth - 1, child.maxDepth));

  // Targets: intersect if both specified, otherwise use the one that is specified
  let targets: string[] | undefined;
  if (parent.targets && child.targets) {
    const parentTargetSet = new Set(parent.targets);
    targets = child.targets.filter((t) => parentTargetSet.has(t));
    if (targets.length === 0) {
      return null; // no common targets
    }
  } else if (parent.targets) {
    targets = [...parent.targets];
  } else if (child.targets) {
    targets = [...child.targets];
  }

  // Rate limit: take the more restrictive
  let rateLimit: DelegationScope['rateLimit'];
  if (parent.rateLimit && child.rateLimit) {
    rateLimit = {
      max: Math.min(parent.rateLimit.max, child.rateLimit.max),
      windowSeconds: Math.max(parent.rateLimit.windowSeconds, child.rateLimit.windowSeconds),
    };
  } else {
    rateLimit = parent.rateLimit ?? child.rateLimit;
  }

  const result: DelegationScope = {
    actions: commonActions,
    maxTier,
    maxDepth,
  };

  if (targets !== undefined) {
    result.targets = targets;
  }

  if (rateLimit !== undefined) {
    result.rateLimit = rateLimit;
  }

  return result;
}

/**
 * Check if a scope allows a specific action (optionally with a target).
 */
export function scopeAllowsAction(
  scope: DelegationScope,
  action: ActionType,
  target?: string,
): boolean {
  if (!scope.actions.includes(action)) {
    return false;
  }

  if (target && scope.targets && scope.targets.length > 0) {
    if (!scope.targets.includes(target)) {
      return false;
    }
  }

  return true;
}

/**
 * Check if the child scope is a subset of the parent scope.
 * A subset means every permission in child exists in parent,
 * and child is equally or more restrictive in all dimensions.
 */
export function isSubScope(parent: DelegationScope, child: DelegationScope): boolean {
  // All child actions must be in parent
  const parentActions = new Set(parent.actions);
  for (const action of child.actions) {
    if (!parentActions.has(action)) {
      return false;
    }
  }

  // Child maxTier must be <= parent maxTier
  if (child.maxTier > parent.maxTier) {
    return false;
  }

  // Child maxDepth must be <= parent maxDepth
  if (child.maxDepth > parent.maxDepth) {
    return false;
  }

  // If parent has targets, child must have subset of those targets
  if (parent.targets && parent.targets.length > 0) {
    if (!child.targets || child.targets.length === 0) {
      return false; // parent restricts targets but child doesn't
    }
    const parentTargetSet = new Set(parent.targets);
    for (const t of child.targets) {
      if (!parentTargetSet.has(t)) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Validate scope constraints, returning errors if any.
 */
export function validateScope(scope: DelegationScope): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!scope.actions || scope.actions.length === 0) {
    errors.push('actions must not be empty');
  }

  if (scope.maxDepth < 0) {
    errors.push('maxDepth must not be negative');
  }

  if (!Number.isInteger(scope.maxDepth)) {
    errors.push('maxDepth must be an integer');
  }

  if (![0, 1, 2, 3].includes(scope.maxTier)) {
    errors.push('maxTier must be 0, 1, 2, or 3');
  }

  if (scope.rateLimit) {
    if (scope.rateLimit.max <= 0) {
      errors.push('rateLimit.max must be positive');
    }
    if (scope.rateLimit.windowSeconds <= 0) {
      errors.push('rateLimit.windowSeconds must be positive');
    }
  }

  return { valid: errors.length === 0, errors };
}
