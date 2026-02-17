/**
 * ZKP Non-Leakage Proof — proves sanitized output contains no vault secrets.
 *
 * Sliding-window approach:
 * 1. Hash each vault entry value
 * 2. For each window size, extract substrings from output
 * 3. Hash each substring window
 * 4. Build Merkle tree of all non-match evidence
 * 5. Verify no windowHash matches any vaultHash
 *
 * Uses only node:crypto — zero external dependencies.
 */

import { createHash } from 'node:crypto';
import type { NonLeakageProof } from './types.js';

/** Window sizes to check (common secret lengths) */
const DEFAULT_WINDOW_SIZES = [16, 20, 24, 32, 40, 48, 64, 128];

/**
 * Compute SHA-256 hash and return as 0x-prefixed hex string.
 */
function sha256(data: string): string {
  return '0x' + createHash('sha256').update(data).digest('hex');
}

/**
 * Compute SHA-256 of a Buffer and return as Buffer.
 */
function sha256Buf(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

/**
 * Convert 0x-prefixed hex to Buffer.
 */
function fromHex(hex: string): Buffer {
  return Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex');
}

/**
 * Convert Buffer to 0x-prefixed hex string.
 */
function toHex(buf: Buffer): string {
  return '0x' + buf.toString('hex');
}

/**
 * Build a simple Merkle root from a list of 0x-hex leaf hashes.
 * Empty list returns all-zeros root.
 */
function buildMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return '0x' + '00'.repeat(32);
  }

  let layer = leaves.map(fromHex);

  while (layer.length > 1) {
    // Duplicate last node if odd
    if (layer.length % 2 !== 0) {
      layer.push(layer[layer.length - 1]);
    }

    const next: Buffer[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1];
      // Sort for consistent ordering
      const [a, b] = Buffer.compare(left, right) <= 0 ? [left, right] : [right, left];
      next.push(sha256Buf(Buffer.concat([a, b])));
    }
    layer = next;
  }

  return toHex(layer[0]);
}

/**
 * Quick leakage check — plain substring match, no proof generation.
 *
 * @returns true if ANY vault entry appears as a substring in the output
 */
export function quickLeakageCheck(output: string, vaultEntries: string[]): boolean {
  for (const entry of vaultEntries) {
    if (entry.length > 0 && output.includes(entry)) {
      return true;
    }
  }
  return false;
}

/**
 * Generate a non-leakage proof for the given output against vault entries.
 *
 * @param output - The sanitized output to prove clean
 * @param vaultEntries - Array of secret values to check against
 * @param windowSizes - Optional custom window sizes (defaults to common secret lengths)
 * @returns Non-leakage proof
 */
export function generateNonLeakageProof(
  output: string,
  vaultEntries: string[],
  windowSizes?: number[],
): NonLeakageProof {
  const sizes = windowSizes ?? DEFAULT_WINDOW_SIZES;
  const timestamp = Date.now();

  // Hash the output
  const outputHash = sha256(output);

  // Hash all vault entries
  const vaultHashes = new Set<string>();
  for (const entry of vaultEntries) {
    if (entry.length > 0) {
      vaultHashes.add(sha256(entry));
    }
  }

  // Include vault entry hashes as the first evidence leaves.
  // This binds the proof to the specific vault entries used.
  const evidenceLeaves: string[] = [];
  const sortedVaultHashes = [...vaultHashes].sort();
  for (const vh of sortedVaultHashes) {
    evidenceLeaves.push(sha256('vault-entry:' + vh));
  }

  // Sliding window: collect evidence hashes and check for matches
  let leaked = false;

  for (const ws of sizes) {
    if (ws > output.length) continue;

    for (let i = 0; i <= output.length - ws; i++) {
      const window = output.substring(i, i + ws);
      const windowHash = sha256(window);

      if (vaultHashes.has(windowHash)) {
        leaked = true;
      }

      // Build evidence leaf: hash of (position + windowHash + result)
      const evidence = sha256(String(i) + windowHash + (vaultHashes.has(windowHash) ? 'match' : 'no-match'));
      evidenceLeaves.push(evidence);
    }
  }

  // Also do a plain substring check for vault entries of any length
  if (!leaked) {
    leaked = quickLeakageCheck(output, vaultEntries);
  }

  // Build Merkle root of all evidence (includes vault hashes + window evidence)
  const exclusionRoot = buildMerkleRoot(evidenceLeaves);

  // Use the largest window size checked
  const maxWindowSize = sizes.reduce((max, s) => (s <= output.length ? Math.max(max, s) : max), 0);

  return {
    outputHash,
    vaultEntryCount: vaultEntries.length,
    windowSize: maxWindowSize || sizes[0],
    exclusionRoot,
    verified: !leaked,
    timestamp,
    scheme: 'sha256-commit',
  };
}

/**
 * Verify a non-leakage proof by recomputing from the original data.
 *
 * @param proof - The proof to verify
 * @param output - The original output text
 * @param vaultEntries - The original vault entries
 * @returns true if the proof is consistent with the provided data
 */
export function verifyNonLeakageProof(
  proof: NonLeakageProof,
  output: string,
  vaultEntries: string[],
): boolean {
  // Check output hash
  const expectedOutputHash = sha256(output);
  if (expectedOutputHash !== proof.outputHash) {
    return false;
  }

  // Check vault entry count
  if (vaultEntries.length !== proof.vaultEntryCount) {
    return false;
  }

  // Recompute the proof and compare exclusion root
  const recomputed = generateNonLeakageProof(output, vaultEntries);
  if (recomputed.exclusionRoot !== proof.exclusionRoot) {
    return false;
  }

  // Verify the claimed verification status matches
  if (recomputed.verified !== proof.verified) {
    return false;
  }

  return true;
}
