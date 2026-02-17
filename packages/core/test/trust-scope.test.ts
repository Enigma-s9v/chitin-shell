import { describe, it, expect } from 'vitest';
import { intersectScopes, scopeAllowsAction, isSubScope, validateScope } from '../src/trust/scope.js';
import type { DelegationScope } from '../src/trust/types.js';

// ---------------------------------------------------------------------------
// intersectScopes
// ---------------------------------------------------------------------------

describe('intersectScopes', () => {
  it('returns intersection of compatible scopes', () => {
    const parent: DelegationScope = {
      actions: ['send_message', 'read_file', 'read_email'],
      maxTier: 2,
      maxDepth: 3,
    };
    const child: DelegationScope = {
      actions: ['send_message', 'read_file'],
      maxTier: 1,
      maxDepth: 2,
    };

    const result = intersectScopes(parent, child);
    expect(result).not.toBeNull();
    expect(result!.actions).toEqual(['send_message', 'read_file']);
    expect(result!.maxTier).toBe(1);
    // maxDepth = min(parent.maxDepth - 1, child.maxDepth) = min(2, 2) = 2
    expect(result!.maxDepth).toBe(2);
  });

  it('returns null when child requests actions not in parent', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 2,
    };
    const child: DelegationScope = {
      actions: ['transfer_funds'],
      maxTier: 1,
      maxDepth: 1,
    };

    expect(intersectScopes(parent, child)).toBeNull();
  });

  it('takes minimum maxTier', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 3,
      maxDepth: 2,
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
    };

    const result = intersectScopes(parent, child);
    expect(result).not.toBeNull();
    expect(result!.maxTier).toBe(1);
  });

  it('takes minimum maxDepth (decremented from parent)', () => {
    const parent: DelegationScope = {
      actions: ['read_file'],
      maxTier: 0,
      maxDepth: 5,
    };
    const child: DelegationScope = {
      actions: ['read_file'],
      maxTier: 0,
      maxDepth: 2,
    };

    const result = intersectScopes(parent, child);
    expect(result).not.toBeNull();
    // min(5 - 1, 2) = min(4, 2) = 2
    expect(result!.maxDepth).toBe(2);
  });

  it('intersects targets when both specified', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
      targets: ['agent-a', 'agent-b', 'agent-c'],
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 0,
      targets: ['agent-b', 'agent-c', 'agent-d'],
    };

    const result = intersectScopes(parent, child);
    expect(result).not.toBeNull();
    expect(result!.targets).toEqual(['agent-b', 'agent-c']);
  });

  it('uses parent targets when child has none', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
      targets: ['agent-a'],
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 0,
    };

    const result = intersectScopes(parent, child);
    expect(result).not.toBeNull();
    expect(result!.targets).toEqual(['agent-a']);
  });

  it('returns null when target intersection is empty', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
      targets: ['agent-a'],
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 0,
      targets: ['agent-b'],
    };

    expect(intersectScopes(parent, child)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// scopeAllowsAction
// ---------------------------------------------------------------------------

describe('scopeAllowsAction', () => {
  it('returns true for an allowed action', () => {
    const scope: DelegationScope = {
      actions: ['send_message', 'read_file'],
      maxTier: 1,
      maxDepth: 0,
    };
    expect(scopeAllowsAction(scope, 'send_message')).toBe(true);
  });

  it('returns false for a disallowed action', () => {
    const scope: DelegationScope = {
      actions: ['read_file'],
      maxTier: 0,
      maxDepth: 0,
    };
    expect(scopeAllowsAction(scope, 'transfer_funds')).toBe(false);
  });

  it('returns false when target is restricted and not in scope', () => {
    const scope: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 0,
      targets: ['agent-a', 'agent-b'],
    };
    expect(scopeAllowsAction(scope, 'send_message', 'agent-c')).toBe(false);
  });

  it('returns true when target is in the restricted set', () => {
    const scope: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 0,
      targets: ['agent-a', 'agent-b'],
    };
    expect(scopeAllowsAction(scope, 'send_message', 'agent-a')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// isSubScope
// ---------------------------------------------------------------------------

describe('isSubScope', () => {
  it('returns true for a valid subset', () => {
    const parent: DelegationScope = {
      actions: ['send_message', 'read_file', 'read_email'],
      maxTier: 2,
      maxDepth: 3,
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 2,
    };
    expect(isSubScope(parent, child)).toBe(true);
  });

  it('returns false when child has actions not in parent', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
    };
    const child: DelegationScope = {
      actions: ['send_message', 'transfer_funds'],
      maxTier: 1,
      maxDepth: 1,
    };
    expect(isSubScope(parent, child)).toBe(false);
  });

  it('returns false when child has higher maxTier', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 2,
      maxDepth: 1,
    };
    expect(isSubScope(parent, child)).toBe(false);
  });

  it('returns false when child has higher maxDepth', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 5,
    };
    expect(isSubScope(parent, child)).toBe(false);
  });

  it('returns false when parent has targets but child does not', () => {
    const parent: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
      targets: ['agent-a'],
    };
    const child: DelegationScope = {
      actions: ['send_message'],
      maxTier: 1,
      maxDepth: 1,
    };
    expect(isSubScope(parent, child)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// validateScope
// ---------------------------------------------------------------------------

describe('validateScope', () => {
  it('rejects empty actions', () => {
    const scope: DelegationScope = {
      actions: [],
      maxTier: 0,
      maxDepth: 0,
    };
    const result = validateScope(scope);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('actions must not be empty');
  });

  it('rejects negative maxDepth', () => {
    const scope: DelegationScope = {
      actions: ['read_file'],
      maxTier: 0,
      maxDepth: -1,
    };
    const result = validateScope(scope);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('maxDepth must not be negative');
  });

  it('accepts a valid scope', () => {
    const scope: DelegationScope = {
      actions: ['send_message', 'read_file'],
      maxTier: 1,
      maxDepth: 2,
      targets: ['agent-x'],
      rateLimit: { max: 10, windowSeconds: 60 },
    };
    const result = validateScope(scope);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});
