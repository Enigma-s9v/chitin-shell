/**
 * ZKP Module — Zero Knowledge Proof framework for Chitin Shell.
 *
 * Provides commitment schemes, provenance proofs, non-leakage proofs,
 * and skill safety proofs. All based on SHA-256 with node:crypto only.
 */

// Types
export type {
  ProofScheme,
  Commitment,
  Opening,
  ProvenanceProof,
  NonLeakageProof,
  SkillSafetyProof,
  SkillSafetyCheck,
  ZkProofBundle,
  ZkProver,
  ZkVerifier,
} from './types.js';

// Commitment
export {
  commit,
  verifyCommitment,
  hashToHex,
  generateBlindingFactor,
} from './commitment.js';

// Provenance
export {
  generateProvenanceProof,
  verifyProvenanceProof,
  verifyProvenanceWithOpening,
} from './provenance.js';

// Non-Leakage
export {
  generateNonLeakageProof,
  verifyNonLeakageProof,
  quickLeakageCheck,
} from './non-leakage.js';

// Skill Safety
export {
  analyzeSkillSafety,
  generateSkillSafetyProof,
  verifySkillSafetyProof,
} from './skill-safety.js';

// Unified Prover & Verifier
export {
  ChitinZkProver,
  ChitinZkVerifier,
} from './verifier.js';
