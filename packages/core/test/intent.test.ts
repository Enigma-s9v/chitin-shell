import { describe, it, expect } from 'vitest';
import { generateKeyPair, signIntent, verifySignature } from '../src/intent/signer.js';
import { createIntent } from '../src/intent/builder.js';
import { validateIntentStructure, validateIntent } from '../src/intent/validator.js';
import type { UnsignedIntent, IntentV1 } from '../src/intent/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid UnsignedIntent for test fixtures */
function makeUnsigned(keyPair: ReturnType<typeof generateKeyPair>): UnsignedIntent {
  return {
    version: '1.0',
    intent_id: 'test-intent-001',
    agent_did: keyPair.did,
    timestamp: new Date().toISOString(),
    action: { type: 'think', params: { query: 'hello' } },
    context: {
      triggered_by: 'user_message',
      session_id: 'session-001',
    },
    nonce: Date.now(),
  };
}

/** Build a signed IntentV1 from a key pair */
function makeSigned(keyPair: ReturnType<typeof generateKeyPair>): IntentV1 {
  const unsigned = makeUnsigned(keyPair);
  const signature = signIntent(unsigned, keyPair.privateKey);
  return { ...unsigned, signature };
}

// ---------------------------------------------------------------------------
// Intent Signer
// ---------------------------------------------------------------------------

describe('Intent Signer', () => {
  it('generateKeyPair() returns valid AgentKeyPair with 32-byte keys and did:key: prefix', () => {
    const kp = generateKeyPair();

    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);

    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBe(32);

    expect(kp.did).toMatch(/^did:key:/);
  });

  it('signIntent() returns a hex string signature', () => {
    const kp = generateKeyPair();
    const unsigned = makeUnsigned(kp);
    const sig = signIntent(unsigned, kp.privateKey);

    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
    expect(sig).toMatch(/^[0-9a-f]+$/i);
  });

  it('verifySignature() returns true for valid signature', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);

    expect(verifySignature(intent, kp.publicKey)).toBe(true);
  });

  it('verifySignature() returns false when payload is tampered', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);

    // Tamper: change action type after signing
    const tampered: IntentV1 = {
      ...intent,
      action: { ...intent.action, type: 'transfer_funds' },
    };

    expect(verifySignature(tampered, kp.publicKey)).toBe(false);
  });

  it('verifySignature() returns false with wrong public key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const intent = makeSigned(kp1);

    expect(verifySignature(intent, kp2.publicKey)).toBe(false);
  });

  it('canonical JSON is deterministic (same intent always produces same signature)', () => {
    const kp = generateKeyPair();

    // Two unsigned intents with identical content but keys inserted in different order
    const base: UnsignedIntent = {
      version: '1.0',
      intent_id: 'determinism-test',
      agent_did: kp.did,
      timestamp: '2026-02-17T00:00:00.000Z',
      action: { type: 'think', params: { a: 1, b: 2 } },
      context: { triggered_by: 'user_message', session_id: 'sess-det' },
      nonce: 12345,
    };

    // Build the same object with reversed key insertion order
    const reversed: UnsignedIntent = {
      nonce: 12345,
      context: { session_id: 'sess-det', triggered_by: 'user_message' },
      action: { type: 'think', params: { b: 2, a: 1 } },
      timestamp: '2026-02-17T00:00:00.000Z',
      agent_did: kp.did,
      intent_id: 'determinism-test',
      version: '1.0',
    };

    const sig1 = signIntent(base, kp.privateKey);
    const sig2 = signIntent(reversed, kp.privateKey);

    expect(sig1).toBe(sig2);
  });
});

// ---------------------------------------------------------------------------
// Intent Builder
// ---------------------------------------------------------------------------

describe('Intent Builder', () => {
  it('createIntent() returns a valid IntentV1 with all required fields', () => {
    const kp = generateKeyPair();
    const intent = createIntent({ action: 'think', params: { q: 'test' } }, kp);

    expect(intent).toHaveProperty('version');
    expect(intent).toHaveProperty('intent_id');
    expect(intent).toHaveProperty('agent_did');
    expect(intent).toHaveProperty('timestamp');
    expect(intent).toHaveProperty('action');
    expect(intent).toHaveProperty('context');
    expect(intent).toHaveProperty('nonce');
    expect(intent).toHaveProperty('signature');
  });

  it('createIntent() sets version to "1.0"', () => {
    const kp = generateKeyPair();
    const intent = createIntent({ action: 'recall', params: {} }, kp);

    expect(intent.version).toBe('1.0');
  });

  it('createIntent() uses keyPair.did as agent_did', () => {
    const kp = generateKeyPair();
    const intent = createIntent({ action: 'summarize', params: {} }, kp);

    expect(intent.agent_did).toBe(kp.did);
  });

  it('createIntent() fills default context (triggered_by: "user_message")', () => {
    const kp = generateKeyPair();
    const intent = createIntent({ action: 'think', params: {} }, kp);

    expect(intent.context.triggered_by).toBe('user_message');
    expect(typeof intent.context.session_id).toBe('string');
    expect(intent.context.session_id.length).toBeGreaterThan(0);
  });

  it('createIntent() respects custom context when provided', () => {
    const kp = generateKeyPair();
    const intent = createIntent(
      {
        action: 'think',
        params: {},
        context: {
          triggered_by: 'scheduled',
          session_id: 'custom-session-42',
          conversation_hash: 'abc123',
        },
      },
      kp,
    );

    expect(intent.context.triggered_by).toBe('scheduled');
    expect(intent.context.session_id).toBe('custom-session-42');
    expect(intent.context.conversation_hash).toBe('abc123');
  });

  it('generated intent has valid signature (verifySignature returns true)', () => {
    const kp = generateKeyPair();
    const intent = createIntent({ action: 'read_file', params: { path: '/tmp/x' } }, kp);

    expect(verifySignature(intent, kp.publicKey)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Intent Validator
// ---------------------------------------------------------------------------

describe('Intent Validator', () => {
  // -- Structure validation -------------------------------------------------

  it('validateIntentStructure() accepts a valid intent', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);

    const result = validateIntentStructure(intent);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validateIntentStructure() rejects null', () => {
    const result = validateIntentStructure(null);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Intent must be a non-null object');
  });

  it('validateIntentStructure() rejects missing version', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const { version: _, ...noVersion } = intent;

    const result = validateIntentStructure(noVersion);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('version must be "1.0"');
  });

  it('validateIntentStructure() rejects invalid agent_did (not starting with "did:")', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const bad = { ...intent, agent_did: 'not-a-did' };

    const result = validateIntentStructure(bad);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('agent_did must be a string starting with "did:"');
  });

  it('validateIntentStructure() rejects invalid timestamp', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const bad = { ...intent, timestamp: 'not-a-date' };

    const result = validateIntentStructure(bad);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('timestamp must be a valid ISO date string');
  });

  it('validateIntentStructure() rejects missing action', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const { action: _, ...noAction } = intent;

    const result = validateIntentStructure(noAction);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('action must be an object');
  });

  it('validateIntentStructure() rejects non-hex signature', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const bad = { ...intent, signature: 'ZZZZ_not_hex!!!' };

    const result = validateIntentStructure(bad);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('signature must be a non-empty hex string');
  });

  it('validateIntentStructure() rejects negative nonce', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);
    const bad = { ...intent, nonce: -1 };

    const result = validateIntentStructure(bad);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('nonce must be a positive integer');
  });

  // -- Full validation (structure + signature) ------------------------------

  it('validateIntent() accepts a properly signed intent', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);

    const result = validateIntent(intent, kp.publicKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validateIntent() rejects tampered intent (valid structure but wrong signature)', () => {
    const kp = generateKeyPair();
    const intent = makeSigned(kp);

    // Tamper params but keep signature intact -> structure valid, sig invalid
    const tampered: IntentV1 = {
      ...intent,
      action: { type: 'think', params: { query: 'tampered' } },
    };

    const result = validateIntent(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Signature verification failed');
  });
});
