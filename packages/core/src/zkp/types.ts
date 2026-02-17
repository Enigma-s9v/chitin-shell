/**
 * ZKP (Zero Knowledge Proof) — Type Definitions
 *
 * Defines types for commitment schemes, provenance proofs,
 * non-leakage proofs, and skill safety proofs.
 *
 * All hashes are 0x-prefixed hex strings (SHA-256).
 */

/** Supported proof schemes */
export type ProofScheme = 'sha256-commit' | 'snark-groth16' | 'snark-plonk';

/** A commitment to a value: C = SHA-256(value || blindingFactor) */
export interface Commitment {
  hash: string;        // 0x-prefixed hex
  scheme: ProofScheme;
  timestamp: number;
}

/** Opening data that reveals the committed value */
export interface Opening {
  value: string;
  blindingFactor: string; // 0x-prefixed hex random nonce
}

/**
 * Provenance Proof — proves an intent was derived from a specific prompt.
 *
 * 1. promptCommitment = H(prompt || nonce)
 * 2. intentHash = H(canonical JSON of intent)
 * 3. derivationBinding = H(promptCommitment || intentHash || timestamp)
 */
export interface ProvenanceProof {
  promptCommitment: string;    // H(prompt || nonce)
  intentHash: string;          // H(canonical JSON of intent)
  derivationBinding: string;   // H(promptCommitment || intentHash || timestamp)
  timestamp: number;
  scheme: ProofScheme;
}

/**
 * Non-Leakage Proof — proves sanitized output contains no vault secrets.
 *
 * Uses a sliding-window approach to check every possible substring
 * of the output against hashed vault entries.
 */
export interface NonLeakageProof {
  outputHash: string;          // H(sanitized output)
  vaultEntryCount: number;     // number of vault entries checked
  windowSize: number;          // sliding window size used
  exclusionRoot: string;       // Merkle root of exclusion evidence
  verified: boolean;
  timestamp: number;
  scheme: ProofScheme;
}

/**
 * Skill Safety Proof — proves static analysis was run on code.
 */
export interface SkillSafetyProof {
  codeHash: string;            // H(skill source code)
  analysisHash: string;        // H(analysis results)
  checks: SkillSafetyCheck[];
  passed: boolean;
  timestamp: number;
  scheme: ProofScheme;
}

/** Individual check result from skill safety analysis */
export interface SkillSafetyCheck {
  name: string;
  passed: boolean;
  details?: string;
}

/** Bundle of multiple proof types */
export interface ZkProofBundle {
  provenance?: ProvenanceProof;
  nonLeakage?: NonLeakageProof;
  skillSafety?: SkillSafetyProof;
  combinedHash: string;        // H(all proof hashes concatenated)
}

/** Prover interface — generates proofs */
export interface ZkProver {
  generateProvenanceProof(prompt: string, intent: unknown): Promise<ProvenanceProof>;
  generateNonLeakageProof(output: string, vaultEntries: string[]): Promise<NonLeakageProof>;
  generateSkillSafetyProof(code: string): Promise<SkillSafetyProof>;
}

/** Verifier interface — verifies proofs */
export interface ZkVerifier {
  verifyProvenanceProof(proof: ProvenanceProof): Promise<boolean>;
  verifyNonLeakageProof(proof: NonLeakageProof, output: string, vaultEntries: string[]): Promise<boolean>;
  verifySkillSafetyProof(proof: SkillSafetyProof, code: string): Promise<boolean>;
  verifyBundle(bundle: ZkProofBundle): Promise<boolean>;
}
