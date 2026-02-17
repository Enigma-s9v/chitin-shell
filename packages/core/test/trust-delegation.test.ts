import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair } from '../src/intent/signer.js';
import { DelegationManager } from '../src/trust/delegation.js';
import { MemoryTrustStore } from '../src/trust/store.js';
import type { DelegationScope, DelegationToken } from '../src/trust/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDid(label: string): string {
  return `did:chitin:84532:0xB204969F768d861024B7aeC3B4aa9dBABF72109d:${label}`;
}

function makeScope(overrides?: Partial<DelegationScope>): DelegationScope {
  return {
    actions: ['send_message', 'read_file'],
    maxTier: 1,
    maxDepth: 2,
    ...overrides,
  };
}

/** Hex-encode a Uint8Array public key */
function hexPub(kp: ReturnType<typeof generateKeyPair>): string {
  return Buffer.from(kp.publicKey).toString('hex');
}

// ---------------------------------------------------------------------------
// DelegationManager — createDelegation
// ---------------------------------------------------------------------------

describe('DelegationManager — createDelegation', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('generates a valid token with all required fields', async () => {
    const kpA = generateKeyPair();
    const didA = makeDid('agent-a');
    const didB = makeDid('agent-b');

    const token = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 86400,
      keyPair: kpA,
    });

    expect(token.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(token.version).toBe(1);
    expect(token.delegator).toBe(didA);
    expect(token.delegate).toBe(didB);
    expect(token.scope.actions).toEqual(['send_message', 'read_file']);
    expect(token.signature).toBeTruthy();
  });

  it('signs the token (non-empty hex signature)', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    expect(token.signature).toMatch(/^[0-9a-f]+$/i);
    expect(token.signature.length).toBeGreaterThan(0);
  });

  it('sets correct timestamps (issuedAt < expiresAt, gap ≈ expiresIn)', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 7200,
      keyPair: kpA,
    });

    const issuedAt = new Date(token.issuedAt).getTime();
    const expiresAt = new Date(token.expiresAt).getTime();
    const diffSeconds = (expiresAt - issuedAt) / 1000;

    expect(issuedAt).toBeLessThan(expiresAt);
    // Allow 2 second tolerance for test execution time
    expect(diffSeconds).toBeGreaterThanOrEqual(7198);
    expect(diffSeconds).toBeLessThanOrEqual(7202);
  });

  it('sets parentTokenId when provided', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();

    // First, create parent delegation A -> B
    const parentToken = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope({ maxDepth: 2 }),
      expiresIn: 86400,
      keyPair: kpA,
    });

    // Then, B sub-delegates to C
    const childToken = await manager.createDelegation({
      delegatorDid: makeDid('b'),
      delegateDid: makeDid('c'),
      scope: makeScope({ maxDepth: 1 }),
      expiresIn: 3600,
      keyPair: kpB,
      parentTokenId: parentToken.id,
    });

    expect(childToken.parentTokenId).toBe(parentToken.id);
  });
});

// ---------------------------------------------------------------------------
// DelegationManager — verifyDelegation
// ---------------------------------------------------------------------------

describe('DelegationManager — verifyDelegation', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('succeeds for a valid token', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    const result = await manager.verifyDelegation(token, hexPub(kpA));
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Valid delegation');
  });

  it('fails for an expired token', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 0, // expires immediately
      keyPair: kpA,
    });

    // Wait a tiny bit to ensure expiry
    await new Promise((r) => setTimeout(r, 10));

    const result = await manager.verifyDelegation(token, hexPub(kpA));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token has expired');
  });

  it('fails for a bad signature (wrong public key)', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    // Verify with wrong key
    const result = await manager.verifyDelegation(token, hexPub(kpB));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Invalid signature');
  });

  it('fails for a revoked token', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    await manager.revokeDelegation(token.id);

    const result = await manager.verifyDelegation(token, hexPub(kpA));
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('Token has been revoked');
  });
});

// ---------------------------------------------------------------------------
// DelegationManager — verifyChain
// ---------------------------------------------------------------------------

describe('DelegationManager — verifyChain', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('succeeds for a valid 2-token chain', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const didA = makeDid('a');
    const didB = makeDid('b');
    const didC = makeDid('c');

    const tokenAB = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: makeScope({ maxDepth: 2 }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    const tokenBC = await manager.createDelegation({
      delegatorDid: didB,
      delegateDid: didC,
      scope: makeScope({ maxDepth: 1 }),
      expiresIn: 1800,
      keyPair: kpB,
      parentTokenId: tokenAB.id,
    });

    const keys = new Map<string, string>();
    keys.set(didA, hexPub(kpA));
    keys.set(didB, hexPub(kpB));

    const result = await manager.verifyChain([tokenAB, tokenBC], keys);
    expect(result.valid).toBe(true);
    expect(result.chain?.rootAgent).toBe(didA);
    expect(result.chain?.leafAgent).toBe(didC);
  });

  it('succeeds for a valid 3-token chain', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const kpC = generateKeyPair();
    const didA = makeDid('a');
    const didB = makeDid('b');
    const didC = makeDid('c');
    const didD = makeDid('d');

    const tokenAB = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: makeScope({ maxDepth: 3 }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    const tokenBC = await manager.createDelegation({
      delegatorDid: didB,
      delegateDid: didC,
      scope: makeScope({ maxDepth: 2 }),
      expiresIn: 3600,
      keyPair: kpB,
      parentTokenId: tokenAB.id,
    });

    const tokenCD = await manager.createDelegation({
      delegatorDid: didC,
      delegateDid: didD,
      scope: makeScope({ maxDepth: 1 }),
      expiresIn: 3600,
      keyPair: kpC,
      parentTokenId: tokenBC.id,
    });

    const keys = new Map<string, string>();
    keys.set(didA, hexPub(kpA));
    keys.set(didB, hexPub(kpB));
    keys.set(didC, hexPub(kpC));

    const result = await manager.verifyChain([tokenAB, tokenBC, tokenCD], keys);
    expect(result.valid).toBe(true);
    expect(result.chain?.rootAgent).toBe(didA);
    expect(result.chain?.leafAgent).toBe(didD);
    expect(result.chain?.tokens).toHaveLength(3);
  });

  it('fails when scope exceeds parent', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const didA = makeDid('a');
    const didB = makeDid('b');
    const didC = makeDid('c');

    const tokenAB = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: { actions: ['read_file'], maxTier: 0, maxDepth: 2 },
      expiresIn: 3600,
      keyPair: kpA,
    });

    // B tries to delegate 'transfer_funds' which A never granted
    // Create manually to bypass createDelegation's checks
    const tokenBC = await manager.createDelegation({
      delegatorDid: didB,
      delegateDid: didC,
      scope: { actions: ['read_file'], maxTier: 0, maxDepth: 0 },
      expiresIn: 3600,
      keyPair: kpB,
      parentTokenId: tokenAB.id,
    });

    // Tamper the token to have a wider scope for chain verification
    const tamperedBC: DelegationToken = {
      ...tokenBC,
      scope: { actions: ['transfer_funds'], maxTier: 3, maxDepth: 0 },
    };

    const keys = new Map<string, string>();
    keys.set(didA, hexPub(kpA));
    keys.set(didB, hexPub(kpB));

    const result = await manager.verifyChain([tokenAB, tamperedBC], keys);
    // Should fail either because sig is invalid (tampered) or scope exceeds parent
    expect(result.valid).toBe(false);
  });

  it('fails when depth limit exceeded', async () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();
    const didA = makeDid('a');
    const didB = makeDid('b');
    const didC = makeDid('c');

    // A delegates with maxDepth=0 (no sub-delegation allowed)
    const tokenAB = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: makeScope({ maxDepth: 0 }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    // B tries to sub-delegate (should fail at chain verification)
    const tokenBC = await manager.createDelegation({
      delegatorDid: didB,
      delegateDid: didC,
      scope: makeScope({ maxDepth: 0 }),
      expiresIn: 3600,
      keyPair: kpB,
    });

    const keys = new Map<string, string>();
    keys.set(didA, hexPub(kpA));
    keys.set(didB, hexPub(kpB));

    const result = await manager.verifyChain([tokenAB, tokenBC], keys);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Depth limit exceeded');
  });

  it('fails when chain has a gap (delegate mismatch)', async () => {
    const kpA = generateKeyPair();
    const kpC = generateKeyPair();
    const didA = makeDid('a');
    const didB = makeDid('b');
    const didC = makeDid('c');
    const didD = makeDid('d');

    // A delegates to B
    const tokenAB = await manager.createDelegation({
      delegatorDid: didA,
      delegateDid: didB,
      scope: makeScope({ maxDepth: 2 }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    // C delegates to D (gap: B != C)
    const tokenCD = await manager.createDelegation({
      delegatorDid: didC,
      delegateDid: didD,
      scope: makeScope({ maxDepth: 0 }),
      expiresIn: 3600,
      keyPair: kpC,
    });

    const keys = new Map<string, string>();
    keys.set(didA, hexPub(kpA));
    keys.set(didC, hexPub(kpC));

    const result = await manager.verifyChain([tokenAB, tokenCD], keys);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Chain gap');
  });
});

// ---------------------------------------------------------------------------
// DelegationManager — revokeDelegation
// ---------------------------------------------------------------------------

describe('DelegationManager — revokeDelegation', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('marks the token as revoked', async () => {
    const kpA = generateKeyPair();
    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: makeDid('b'),
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    await manager.revokeDelegation(token.id);

    const entry = await store.get(token.id);
    expect(entry?.revoked).toBe(true);
    expect(entry?.revokedAt).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// DelegationManager — checkAuthority
// ---------------------------------------------------------------------------

describe('DelegationManager — checkAuthority', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('finds valid delegation for authorized action', async () => {
    const kpA = generateKeyPair();
    const didB = makeDid('b');

    await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope({ actions: ['send_message'] }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    const result = await manager.checkAuthority(didB, 'send_message');
    expect(result.valid).toBe(true);
    expect(result.reason).toBe('Delegated authority found');
  });

  it('rejects expired delegation', async () => {
    const kpA = generateKeyPair();
    const didB = makeDid('b');

    await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 0,
      keyPair: kpA,
    });

    await new Promise((r) => setTimeout(r, 10));

    const result = await manager.checkAuthority(didB, 'send_message');
    expect(result.valid).toBe(false);
  });

  it('rejects revoked delegation', async () => {
    const kpA = generateKeyPair();
    const didB = makeDid('b');

    const token = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    await manager.revokeDelegation(token.id);

    const result = await manager.checkAuthority(didB, 'send_message');
    expect(result.valid).toBe(false);
  });

  it('rejects unauthorized action', async () => {
    const kpA = generateKeyPair();
    const didB = makeDid('b');

    await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope({ actions: ['read_file'] }),
      expiresIn: 3600,
      keyPair: kpA,
    });

    const result = await manager.checkAuthority(didB, 'transfer_funds');
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DelegationManager — getActiveDelegations
// ---------------------------------------------------------------------------

describe('DelegationManager — getActiveDelegations', () => {
  let manager: DelegationManager;
  let store: MemoryTrustStore;

  beforeEach(() => {
    store = new MemoryTrustStore();
    manager = new DelegationManager(store);
  });

  it('returns only non-expired non-revoked delegations', async () => {
    const kpA = generateKeyPair();
    const didB = makeDid('b');

    // Active delegation
    const activeToken = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });

    // Expired delegation
    await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 0,
      keyPair: kpA,
    });

    // Revoked delegation
    const revokedToken = await manager.createDelegation({
      delegatorDid: makeDid('a'),
      delegateDid: didB,
      scope: makeScope(),
      expiresIn: 3600,
      keyPair: kpA,
    });
    await manager.revokeDelegation(revokedToken.id);

    await new Promise((r) => setTimeout(r, 10));

    const active = await manager.getActiveDelegations(didB);
    expect(active).toHaveLength(1);
    expect(active[0].id).toBe(activeToken.id);
  });
});

// ---------------------------------------------------------------------------
// MemoryTrustStore — CRUD
// ---------------------------------------------------------------------------

describe('MemoryTrustStore — basic CRUD', () => {
  it('stores, retrieves, queries, and revokes tokens', async () => {
    const store = new MemoryTrustStore();

    const token: DelegationToken = {
      id: 'test-id-001',
      version: 1,
      delegator: 'did:chitin:1:0x0:delegator',
      delegate: 'did:chitin:1:0x0:delegate',
      scope: {
        actions: ['read_file'],
        maxTier: 0,
        maxDepth: 0,
      },
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      signature: 'abcdef',
    };

    // Store
    await store.store(token);

    // Get
    const entry = await store.get('test-id-001');
    expect(entry).not.toBeNull();
    expect(entry!.token.id).toBe('test-id-001');
    expect(entry!.revoked).toBe(false);

    // Get non-existent
    const missing = await store.get('nonexistent');
    expect(missing).toBeNull();

    // getByDelegate
    const byDelegate = await store.getByDelegate('did:chitin:1:0x0:delegate');
    expect(byDelegate).toHaveLength(1);

    // getByDelegator
    const byDelegator = await store.getByDelegator('did:chitin:1:0x0:delegator');
    expect(byDelegator).toHaveLength(1);

    // Revoke
    await store.revoke('test-id-001');
    expect(await store.isRevoked('test-id-001')).toBe(true);

    const afterRevoke = await store.get('test-id-001');
    expect(afterRevoke!.revoked).toBe(true);
    expect(afterRevoke!.revokedAt).toBeTruthy();

    // isRevoked for non-existent returns false
    expect(await store.isRevoked('nonexistent')).toBe(false);
  });
});
