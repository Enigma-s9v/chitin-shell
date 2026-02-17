import { describe, it, expect } from 'vitest';
import {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  hashAuditEntry,
} from '../src/audit/merkle.js';
import type { AuditEntry } from '../src/audit/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: 'entry-001',
    timestamp: '2026-02-17T00:00:00.000Z',
    intent_id: 'intent-001',
    agent_did: 'did:chitin:test-agent',
    action_type: 'send_message',
    tier: 1,
    decision: 'approved',
    reason: 'Policy allows tier 1 actions',
    ...overrides,
  };
}

function makeEntries(count: number): AuditEntry[] {
  return Array.from({ length: count }, (_, i) =>
    makeEntry({
      id: `entry-${String(i + 1).padStart(3, '0')}`,
      timestamp: new Date(Date.UTC(2026, 1, 17, 0, 0, i)).toISOString(),
      intent_id: `intent-${String(i + 1).padStart(3, '0')}`,
    }),
  );
}

// ---------------------------------------------------------------------------
// hashAuditEntry
// ---------------------------------------------------------------------------

describe('hashAuditEntry', () => {
  it('is deterministic — same entry produces same hash', () => {
    const entry = makeEntry();
    const hash1 = hashAuditEntry(entry);
    const hash2 = hashAuditEntry(entry);
    expect(hash1.equals(hash2)).toBe(true);
  });

  it('produces different hashes for different entries', () => {
    const entry1 = makeEntry({ id: 'a' });
    const entry2 = makeEntry({ id: 'b' });
    expect(hashAuditEntry(entry1).equals(hashAuditEntry(entry2))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildMerkleTree
// ---------------------------------------------------------------------------

describe('buildMerkleTree', () => {
  it('returns zero root for empty entries', () => {
    const { root, leaves, tree } = buildMerkleTree([]);
    expect(root).toBe('0x' + '00'.repeat(32));
    expect(leaves).toHaveLength(0);
    expect(tree).toHaveLength(0);
  });

  it('builds tree from single entry', () => {
    const entries = makeEntries(1);
    const { root, leaves, tree } = buildMerkleTree(entries);

    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(leaves).toHaveLength(1);
    // Single leaf: root = leaf
    expect(root).toBe(leaves[0]);
    expect(tree).toHaveLength(1);
  });

  it('builds tree from 2 entries', () => {
    const entries = makeEntries(2);
    const { root, leaves, tree } = buildMerkleTree(entries);

    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(leaves).toHaveLength(2);
    // 2 leaves -> root layer = 1 hash
    expect(tree).toHaveLength(2);
    expect(tree[0]).toHaveLength(2); // leaf layer
    expect(tree[1]).toHaveLength(1); // root layer
  });

  it('builds tree from 4 entries (perfect binary tree)', () => {
    const entries = makeEntries(4);
    const { root, leaves, tree } = buildMerkleTree(entries);

    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(leaves).toHaveLength(4);
    expect(tree).toHaveLength(3);
    expect(tree[0]).toHaveLength(4); // leaves
    expect(tree[1]).toHaveLength(2); // intermediate
    expect(tree[2]).toHaveLength(1); // root
  });

  it('builds tree from 5 entries (odd — last duplicated)', () => {
    const entries = makeEntries(5);
    const { root, leaves, tree } = buildMerkleTree(entries);

    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(leaves).toHaveLength(5);
    // 5 leaves -> 3 intermediate (5+dup=6, /2=3) -> 2 (3+dup=4, /2=2) -> 1 root
    expect(tree[0]).toHaveLength(5);
    expect(tree[tree.length - 1]).toHaveLength(1);
  });

  it('is deterministic — same entries produce same root', () => {
    const entries = makeEntries(4);
    const { root: root1 } = buildMerkleTree(entries);
    const { root: root2 } = buildMerkleTree(entries);
    expect(root1).toBe(root2);
  });

  it('produces different roots for different entries', () => {
    const entries1 = makeEntries(3);
    const entries2 = [
      ...makeEntries(2),
      makeEntry({ id: 'different', reason: 'altered entry' }),
    ];
    const { root: root1 } = buildMerkleTree(entries1);
    const { root: root2 } = buildMerkleTree(entries2);
    expect(root1).not.toBe(root2);
  });
});

// ---------------------------------------------------------------------------
// generateMerkleProof + verifyMerkleProof
// ---------------------------------------------------------------------------

describe('generateMerkleProof', () => {
  it('returns null for empty tree', () => {
    expect(generateMerkleProof([], 0)).toBeNull();
  });

  it('returns null for out-of-range index', () => {
    const { tree } = buildMerkleTree(makeEntries(4));
    expect(generateMerkleProof(tree, -1)).toBeNull();
    expect(generateMerkleProof(tree, 4)).toBeNull();
  });

  it('generates a valid proof for each leaf in a 4-entry tree', () => {
    const entries = makeEntries(4);
    const { root, leaves, tree } = buildMerkleTree(entries);

    for (let i = 0; i < leaves.length; i++) {
      const proofData = generateMerkleProof(tree, i);
      expect(proofData).not.toBeNull();
      expect(proofData!.index).toBe(i);
      expect(proofData!.proof.length).toBeGreaterThan(0);
    }
  });
});

describe('verifyMerkleProof', () => {
  it('returns true for a valid proof', () => {
    const entries = makeEntries(8);
    const { root, tree } = buildMerkleTree(entries);

    const proofData = generateMerkleProof(tree, 3)!;
    const valid = verifyMerkleProof(
      root,
      tree[0][3],
      proofData.proof,
      proofData.index,
    );
    expect(valid).toBe(true);
  });

  it('returns true for a single-entry tree (empty proof)', () => {
    const entries = makeEntries(1);
    const { root, tree } = buildMerkleTree(entries);

    const proofData = generateMerkleProof(tree, 0)!;
    expect(proofData.proof).toHaveLength(0);
    const valid = verifyMerkleProof(
      root,
      tree[0][0],
      proofData.proof,
      proofData.index,
    );
    expect(valid).toBe(true);
  });

  it('returns false for a tampered leaf', () => {
    const entries = makeEntries(4);
    const { root, tree } = buildMerkleTree(entries);

    const proofData = generateMerkleProof(tree, 0)!;
    const tamperedLeaf = '0x' + 'ff'.repeat(32);
    const valid = verifyMerkleProof(
      root,
      tamperedLeaf,
      proofData.proof,
      proofData.index,
    );
    expect(valid).toBe(false);
  });

  it('returns false for a wrong root', () => {
    const entries = makeEntries(4);
    const { tree } = buildMerkleTree(entries);

    const wrongRoot = '0x' + 'ab'.repeat(32);
    const proofData = generateMerkleProof(tree, 0)!;
    const valid = verifyMerkleProof(
      wrongRoot,
      tree[0][0],
      proofData.proof,
      proofData.index,
    );
    expect(valid).toBe(false);
  });

  it('returns false for a wrong index', () => {
    const entries = makeEntries(4);
    const { root, tree } = buildMerkleTree(entries);

    // Generate proof for index 0 but verify against leaf at index 1
    const proofData = generateMerkleProof(tree, 0)!;
    const valid = verifyMerkleProof(
      root,
      tree[0][1], // wrong leaf for this proof
      proofData.proof,
      proofData.index,
    );
    expect(valid).toBe(false);
  });

  it('verifies all leaves in a 5-entry (odd) tree', () => {
    const entries = makeEntries(5);
    const { root, tree } = buildMerkleTree(entries);

    for (let i = 0; i < 5; i++) {
      const proofData = generateMerkleProof(tree, i)!;
      const valid = verifyMerkleProof(
        root,
        tree[0][i],
        proofData.proof,
        proofData.index,
      );
      expect(valid).toBe(true);
    }
  });
});
