/**
 * ZKP Commitment Scheme — SHA-256 based.
 *
 * Commitment: C = SHA-256(value || blindingFactor)
 * All hashes are returned as 0x-prefixed hex strings.
 *
 * Uses only node:crypto — zero external dependencies.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { Commitment, Opening } from './types.js';

/**
 * Compute SHA-256 hash and return as 0x-prefixed hex string.
 */
function sha256(data: string | Buffer): string {
  const hash = createHash('sha256').update(data).digest('hex');
  return '0x' + hash;
}

/**
 * Generate a 32-byte random blinding factor as 0x-prefixed hex.
 */
export function generateBlindingFactor(): string {
  return '0x' + randomBytes(32).toString('hex');
}

/**
 * Hash any string to a 0x-prefixed hex string (SHA-256).
 */
export function hashToHex(data: string): string {
  return sha256(data);
}

/**
 * Generate a commitment to a value.
 *
 * C = SHA-256(value || blindingFactor)
 *
 * @returns commitment and opening (value + blindingFactor)
 */
export function commit(value: string): { commitment: Commitment; opening: Opening } {
  const blindingFactor = generateBlindingFactor();
  const hash = sha256(value + blindingFactor);

  const commitment: Commitment = {
    hash,
    scheme: 'sha256-commit',
    timestamp: Date.now(),
  };

  const opening: Opening = {
    value,
    blindingFactor,
  };

  return { commitment, opening };
}

/**
 * Verify that an opening matches a commitment.
 *
 * Recomputes SHA-256(value || blindingFactor) and compares to commitment hash.
 */
export function verifyCommitment(commitment: Commitment, opening: Opening): boolean {
  const recomputed = sha256(opening.value + opening.blindingFactor);
  return recomputed === commitment.hash;
}
