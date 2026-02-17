import { describe, it, expect } from 'vitest';
import {
  generateProvenanceProof,
  verifyProvenanceProof,
  verifyProvenanceWithOpening,
} from '../src/zkp/provenance.js';
import { generateBlindingFactor, hashToHex } from '../src/zkp/commitment.js';
import type { IntentV1 } from '../src/intent/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIntent(overrides?: Partial<IntentV1>): IntentV1 {
  return {
    version: '1.0',
    intent_id: 'intent-prov-001',
    agent_did: 'did:key:z6MkTest',
    timestamp: '2026-02-17T12:00:00.000Z',
    action: { type: 'think', params: { query: 'hello' } },
    context: { triggered_by: 'user_message', session_id: 'sess-001' },
    nonce: 42,
    signature: 'deadbeef',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Provenance Proof Generation
// ---------------------------------------------------------------------------

describe('Provenance Proof Generation', () => {
  it('generateProvenanceProof() creates valid proof', () => {
    const proof = generateProvenanceProof('test prompt', makeIntent());

    expect(proof.promptCommitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.intentHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.derivationBinding).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.scheme).toBe('sha256-commit');
    expect(typeof proof.timestamp).toBe('number');
  });

  it('generateProvenanceProof() is deterministic with same blinding factor', () => {
    const bf = generateBlindingFactor();
    const intent = makeIntent();

    // Need to make timestamp deterministic too — we can't control it directly,
    // but we verify the prompt commitment and intent hash are the same
    const proof1 = generateProvenanceProof('same prompt', intent, bf);
    const proof2 = generateProvenanceProof('same prompt', intent, bf);

    expect(proof1.promptCommitment).toBe(proof2.promptCommitment);
    expect(proof1.intentHash).toBe(proof2.intentHash);
  });

  it('generateProvenanceProof() differs with different prompts', () => {
    const bf = generateBlindingFactor();
    const intent = makeIntent();

    const proof1 = generateProvenanceProof('prompt A', intent, bf);
    const proof2 = generateProvenanceProof('prompt B', intent, bf);

    expect(proof1.promptCommitment).not.toBe(proof2.promptCommitment);
    // Intent hash should be the same (same intent)
    expect(proof1.intentHash).toBe(proof2.intentHash);
  });

  it('generateProvenanceProof() differs with different intents', () => {
    const bf = generateBlindingFactor();

    const proof1 = generateProvenanceProof('same prompt', makeIntent({ intent_id: 'a' }), bf);
    const proof2 = generateProvenanceProof('same prompt', makeIntent({ intent_id: 'b' }), bf);

    // Prompt commitment should be the same (same prompt + bf)
    expect(proof1.promptCommitment).toBe(proof2.promptCommitment);
    // Intent hash should differ
    expect(proof1.intentHash).not.toBe(proof2.intentHash);
  });

  it('generateProvenanceProof() uses sha256-commit scheme', () => {
    const proof = generateProvenanceProof('prompt', makeIntent());
    expect(proof.scheme).toBe('sha256-commit');
  });
});

// ---------------------------------------------------------------------------
// Provenance Proof Verification
// ---------------------------------------------------------------------------

describe('Provenance Proof Verification', () => {
  it('verifyProvenanceProof() succeeds for valid proof', () => {
    const proof = generateProvenanceProof('my prompt', makeIntent());
    expect(verifyProvenanceProof(proof)).toBe(true);
  });

  it('verifyProvenanceProof() fails with tampered derivationBinding', () => {
    const proof = generateProvenanceProof('my prompt', makeIntent());
    const tampered = { ...proof, derivationBinding: '0x' + 'aa'.repeat(32) };
    expect(verifyProvenanceProof(tampered)).toBe(false);
  });

  it('verifyProvenanceProof() fails with tampered intentHash', () => {
    const proof = generateProvenanceProof('my prompt', makeIntent());
    const tampered = { ...proof, intentHash: '0x' + 'bb'.repeat(32) };
    expect(verifyProvenanceProof(tampered)).toBe(false);
  });

  it('verifyProvenanceProof() fails with tampered timestamp', () => {
    const proof = generateProvenanceProof('my prompt', makeIntent());
    const tampered = { ...proof, timestamp: proof.timestamp + 1000 };
    expect(verifyProvenanceProof(tampered)).toBe(false);
  });

  it('verifyProvenanceProof() fails with tampered promptCommitment', () => {
    const proof = generateProvenanceProof('my prompt', makeIntent());
    const tampered = { ...proof, promptCommitment: '0x' + 'cc'.repeat(32) };
    expect(verifyProvenanceProof(tampered)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Provenance Proof Verification with Opening
// ---------------------------------------------------------------------------

describe('Provenance Proof with Opening', () => {
  it('verifyProvenanceWithOpening() succeeds with correct opening', () => {
    const bf = generateBlindingFactor();
    const prompt = 'the secret prompt';
    const proof = generateProvenanceProof(prompt, makeIntent(), bf);

    const opening = { value: prompt, blindingFactor: bf };
    expect(verifyProvenanceWithOpening(proof, opening)).toBe(true);
  });

  it('verifyProvenanceWithOpening() fails with wrong prompt', () => {
    const bf = generateBlindingFactor();
    const proof = generateProvenanceProof('real prompt', makeIntent(), bf);

    const wrongOpening = { value: 'fake prompt', blindingFactor: bf };
    expect(verifyProvenanceWithOpening(proof, wrongOpening)).toBe(false);
  });

  it('verifyProvenanceWithOpening() fails with wrong blinding factor', () => {
    const bf = generateBlindingFactor();
    const prompt = 'my prompt';
    const proof = generateProvenanceProof(prompt, makeIntent(), bf);

    const wrongOpening = { value: prompt, blindingFactor: generateBlindingFactor() };
    expect(verifyProvenanceWithOpening(proof, wrongOpening)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

describe('Intent Canonicalization', () => {
  it('canonicalization is stable regardless of key order', () => {
    // Two intents with same data but different key insertion order
    const intent1: IntentV1 = {
      version: '1.0',
      intent_id: 'id-stable',
      agent_did: 'did:key:z6MkStable',
      timestamp: '2026-01-01T00:00:00.000Z',
      action: { type: 'think', params: { a: 1, b: 2 } },
      context: { triggered_by: 'user_message', session_id: 'sess' },
      nonce: 1,
      signature: 'abc',
    };

    const intent2: IntentV1 = {
      signature: 'abc',
      nonce: 1,
      context: { session_id: 'sess', triggered_by: 'user_message' },
      action: { type: 'think', params: { b: 2, a: 1 } },
      timestamp: '2026-01-01T00:00:00.000Z',
      agent_did: 'did:key:z6MkStable',
      intent_id: 'id-stable',
      version: '1.0',
    };

    const bf = generateBlindingFactor();
    const proof1 = generateProvenanceProof('prompt', intent1, bf);
    const proof2 = generateProvenanceProof('prompt', intent2, bf);

    expect(proof1.intentHash).toBe(proof2.intentHash);
  });
});
