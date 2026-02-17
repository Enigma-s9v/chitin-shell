/**
 * ZKP Unified Verifier & Prover — implements ZkVerifier and ZkProver interfaces.
 *
 * Delegates to the individual proof modules for generation and verification.
 * Also provides a bundle generator that combines multiple proofs.
 *
 * Uses only node:crypto — zero external dependencies.
 */

import { createHash } from 'node:crypto';
import type { IntentV1 } from '../intent/types.js';
import type {
  NonLeakageProof,
  ProvenanceProof,
  SkillSafetyProof,
  ZkProofBundle,
  ZkProver,
  ZkVerifier,
} from './types.js';
import {
  generateProvenanceProof as genProvenance,
  verifyProvenanceProof as verProvenance,
} from './provenance.js';
import {
  generateNonLeakageProof as genNonLeakage,
  verifyNonLeakageProof as verNonLeakage,
} from './non-leakage.js';
import {
  generateSkillSafetyProof as genSkillSafety,
  verifySkillSafetyProof as verSkillSafety,
} from './skill-safety.js';

/**
 * Compute SHA-256 hash and return as 0x-prefixed hex string.
 */
function sha256(data: string): string {
  return '0x' + createHash('sha256').update(data).digest('hex');
}

/**
 * Compute the combined hash for a proof bundle.
 * Concatenates all available proof hashes and hashes the result.
 */
function computeCombinedHash(bundle: Omit<ZkProofBundle, 'combinedHash'>): string {
  let concat = '';

  if (bundle.provenance) {
    concat += bundle.provenance.promptCommitment;
    concat += bundle.provenance.intentHash;
    concat += bundle.provenance.derivationBinding;
  }

  if (bundle.nonLeakage) {
    concat += bundle.nonLeakage.outputHash;
    concat += bundle.nonLeakage.exclusionRoot;
  }

  if (bundle.skillSafety) {
    concat += bundle.skillSafety.codeHash;
    concat += bundle.skillSafety.analysisHash;
  }

  // If nothing provided, hash the empty string
  return sha256(concat);
}

/**
 * Unified ZKP Verifier — verifies all proof types.
 */
export class ChitinZkVerifier implements ZkVerifier {
  async verifyProvenanceProof(proof: ProvenanceProof): Promise<boolean> {
    return verProvenance(proof);
  }

  async verifyNonLeakageProof(
    proof: NonLeakageProof,
    output: string,
    vaultEntries: string[],
  ): Promise<boolean> {
    return verNonLeakage(proof, output, vaultEntries);
  }

  async verifySkillSafetyProof(
    proof: SkillSafetyProof,
    code: string,
  ): Promise<boolean> {
    return verSkillSafety(proof, code);
  }

  async verifyBundle(bundle: ZkProofBundle): Promise<boolean> {
    // Verify combined hash
    const expectedCombinedHash = computeCombinedHash(bundle);
    if (expectedCombinedHash !== bundle.combinedHash) {
      return false;
    }

    // Verify individual proofs that are present
    if (bundle.provenance) {
      const valid = await this.verifyProvenanceProof(bundle.provenance);
      if (!valid) return false;
    }

    // NonLeakage and SkillSafety require original data, so we can only
    // verify the combined hash consistency here. Full verification
    // requires the original data and should be done separately.

    return true;
  }
}

/**
 * Unified ZKP Prover — generates all proof types.
 */
export class ChitinZkProver implements ZkProver {
  async generateProvenanceProof(
    prompt: string,
    intent: unknown,
  ): Promise<ProvenanceProof> {
    return genProvenance(prompt, intent as IntentV1);
  }

  async generateNonLeakageProof(
    output: string,
    vaultEntries: string[],
  ): Promise<NonLeakageProof> {
    return genNonLeakage(output, vaultEntries);
  }

  async generateSkillSafetyProof(code: string): Promise<SkillSafetyProof> {
    return genSkillSafety(code);
  }

  /**
   * Generate a bundle combining multiple proof types.
   *
   * Only generates proofs for parameters that are provided.
   */
  async generateBundle(params: {
    prompt?: string;
    intent?: unknown;
    output?: string;
    vaultEntries?: string[];
    code?: string;
  }): Promise<ZkProofBundle> {
    const bundle: Omit<ZkProofBundle, 'combinedHash'> = {};

    if (params.prompt !== undefined && params.intent !== undefined) {
      bundle.provenance = await this.generateProvenanceProof(
        params.prompt,
        params.intent,
      );
    }

    if (params.output !== undefined && params.vaultEntries !== undefined) {
      bundle.nonLeakage = await this.generateNonLeakageProof(
        params.output,
        params.vaultEntries,
      );
    }

    if (params.code !== undefined) {
      bundle.skillSafety = await this.generateSkillSafetyProof(params.code);
    }

    const combinedHash = computeCombinedHash(bundle);

    return { ...bundle, combinedHash };
  }
}
