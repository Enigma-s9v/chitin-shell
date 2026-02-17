/**
 * Merkle Tree — SHA-256 based Merkle tree for audit log anchoring.
 *
 * Leaves are SHA-256 of the canonical JSON of each AuditEntry.
 * Internal nodes are SHA-256(left + right), with left < right for consistent ordering.
 * If there is an odd number of nodes at any level, the last node is duplicated.
 *
 * All hashes are hex-encoded strings prefixed with "0x".
 *
 * NOTE: In production, leaves should use keccak256 for on-chain compatibility
 * with Solidity's keccak256. For the TypeScript implementation, SHA-256 is used
 * because proof verification also happens off-chain.
 */

import { createHash } from 'node:crypto';
import type { AuditEntry } from './types.js';

/** Compute SHA-256 hash of a string or Buffer */
function sha256(data: string | Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

/** Convert a Buffer to a 0x-prefixed hex string */
function toHex(buf: Buffer): string {
  return '0x' + buf.toString('hex');
}

/** Convert a 0x-prefixed hex string to a Buffer */
function fromHex(hex: string): Buffer {
  return Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex');
}

/**
 * Compute the hash of an audit entry (for leaf nodes).
 * Uses canonical JSON (keys sorted deterministically via JSON.stringify).
 */
export function hashAuditEntry(entry: AuditEntry): Buffer {
  // Use sorted-key JSON for canonical representation
  const canonical = JSON.stringify(entry, Object.keys(entry).sort());
  return sha256(canonical);
}

/**
 * Build a Merkle tree from audit entries.
 *
 * @returns Object with root, leaves, and full tree layers.
 *          Returns root as "0x" + "00".repeat(32) for empty input.
 */
export function buildMerkleTree(entries: AuditEntry[]): {
  root: string;
  leaves: string[];
  tree: string[][];
} {
  if (entries.length === 0) {
    return {
      root: '0x' + '00'.repeat(32),
      leaves: [],
      tree: [],
    };
  }

  // Build leaf layer
  const leaves = entries.map((entry) => toHex(hashAuditEntry(entry)));

  // Build tree bottom-up
  const tree: string[][] = [leaves];
  let currentLayer = leaves;

  while (currentLayer.length > 1) {
    const nextLayer: string[] = [];

    // If odd number of nodes, duplicate the last one
    if (currentLayer.length % 2 !== 0) {
      currentLayer = [...currentLayer, currentLayer[currentLayer.length - 1]];
    }

    for (let i = 0; i < currentLayer.length; i += 2) {
      const left = fromHex(currentLayer[i]);
      const right = fromHex(currentLayer[i + 1]);

      // Sort for consistent ordering: left < right
      const [sortedLeft, sortedRight] =
        Buffer.compare(left, right) <= 0 ? [left, right] : [right, left];

      const parent = sha256(Buffer.concat([sortedLeft, sortedRight]));
      nextLayer.push(toHex(parent));
    }

    tree.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    leaves,
    tree,
  };
}

/**
 * Generate a Merkle proof for a specific entry by leaf index.
 *
 * @param tree - Full tree layers from buildMerkleTree
 * @param leafIndex - Index of the leaf in the first layer
 * @returns Proof object with sibling hashes and the original index
 */
export function generateMerkleProof(
  tree: string[][],
  leafIndex: number,
): { proof: string[]; index: number } | null {
  if (tree.length === 0 || leafIndex < 0 || leafIndex >= tree[0].length) {
    return null;
  }

  const proof: string[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    let layer = tree[level];

    // If odd number of nodes, duplicate the last one (same logic as build)
    if (layer.length % 2 !== 0) {
      layer = [...layer, layer[layer.length - 1]];
    }

    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    proof.push(layer[siblingIdx]);

    // Move to parent index
    idx = Math.floor(idx / 2);
  }

  return { proof, index: leafIndex };
}

/**
 * Verify a Merkle proof against a root.
 *
 * @param root - Expected root hash (0x-prefixed hex)
 * @param leaf - Leaf hash to verify (0x-prefixed hex)
 * @param proof - Array of sibling hashes (0x-prefixed hex)
 * @param index - Original leaf index
 * @returns true if the proof is valid
 */
export function verifyMerkleProof(
  root: string,
  leaf: string,
  proof: string[],
  index: number,
): boolean {
  let current = fromHex(leaf);
  let idx = index;

  for (const siblingHex of proof) {
    const sibling = fromHex(siblingHex);

    // Sort for consistent ordering (same as build)
    const [left, right] =
      Buffer.compare(current, sibling) <= 0
        ? [current, sibling]
        : [sibling, current];

    current = sha256(Buffer.concat([left, right]));
    idx = Math.floor(idx / 2);
  }

  return toHex(current) === root;
}
