/**
 * ZKP Provenance Proof — proves an intent was derived from a specific prompt.
 *
 * 1. promptCommitment = H(prompt || blindingFactor)
 * 2. intentHash = H(canonical JSON of intent)
 * 3. derivationBinding = H(promptCommitment || intentHash || timestamp)
 *
 * Uses only node:crypto — zero external dependencies.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { IntentV1 } from '../intent/types.js';
import type { Opening, ProvenanceProof } from './types.js';

/**
 * Compute SHA-256 hash and return as 0x-prefixed hex string.
 */
function sha256(data: string): string {
  return '0x' + createHash('sha256').update(data).digest('hex');
}

/**
 * Canonical JSON serialization — sorted keys recursively.
 * Ensures deterministic hashing regardless of key insertion order.
 */
function canonicalizeIntent(intent: IntentV1): string {
  return JSON.stringify(intent, sortedReplacer);
}

/**
 * JSON.stringify replacer that sorts object keys.
 */
function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

/**
 * Generate a provenance proof binding a prompt to an intent.
 *
 * @param prompt - The original prompt text
 * @param intent - The derived intent
 * @param blindingFactor - Optional pre-generated blinding factor (0x-prefixed hex).
 *                         If omitted, a random one is generated.
 * @returns Provenance proof
 */
export function generateProvenanceProof(
  prompt: string,
  intent: IntentV1,
  blindingFactor?: string,
): ProvenanceProof {
  const bf = blindingFactor ?? ('0x' + randomBytes(32).toString('hex'));
  const timestamp = Date.now();

  // Step 1: Commit to prompt
  const promptCommitment = sha256(prompt + bf);

  // Step 2: Hash intent canonically
  const intentHash = sha256(canonicalizeIntent(intent));

  // Step 3: Bind prompt commitment to intent hash with timestamp
  const derivationBinding = sha256(promptCommitment + intentHash + String(timestamp));

  return {
    promptCommitment,
    intentHash,
    derivationBinding,
    timestamp,
    scheme: 'sha256-commit',
  };
}

/**
 * Verify provenance proof internal consistency.
 *
 * Checks that derivationBinding = H(promptCommitment || intentHash || timestamp).
 * Does NOT verify that the prompt matches the commitment (needs the opening for that).
 */
export function verifyProvenanceProof(proof: ProvenanceProof): boolean {
  const expectedBinding = sha256(
    proof.promptCommitment + proof.intentHash + String(proof.timestamp),
  );
  return expectedBinding === proof.derivationBinding;
}

/**
 * Verify provenance proof with opening — proves a specific prompt was committed.
 *
 * @param proof - The provenance proof to verify
 * @param opening - The opening containing the original prompt and blinding factor
 * @returns true if the prompt matches the commitment AND the binding is valid
 */
export function verifyProvenanceWithOpening(
  proof: ProvenanceProof,
  opening: Opening,
): boolean {
  // Recompute prompt commitment: H(prompt || blindingFactor)
  const recomputedCommitment = sha256(opening.value + opening.blindingFactor);
  if (recomputedCommitment !== proof.promptCommitment) {
    return false;
  }

  // Also verify the binding itself
  return verifyProvenanceProof(proof);
}
