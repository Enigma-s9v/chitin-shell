import { describe, it, expect } from 'vitest';
import {
  commit,
  verifyCommitment,
  hashToHex,
  generateBlindingFactor,
} from '../src/zkp/commitment.js';

// ---------------------------------------------------------------------------
// Commitment Scheme
// ---------------------------------------------------------------------------

describe('Commitment Scheme', () => {
  it('commit() generates unique commitments for same value', () => {
    const { commitment: c1 } = commit('secret');
    const { commitment: c2 } = commit('secret');

    // Different blinding factors → different hashes
    expect(c1.hash).not.toBe(c2.hash);
  });

  it('commit() generates unique commitments for different values', () => {
    const { commitment: c1 } = commit('alpha');
    const { commitment: c2 } = commit('beta');

    expect(c1.hash).not.toBe(c2.hash);
  });

  it('commit() includes timestamp', () => {
    const before = Date.now();
    const { commitment } = commit('value');
    const after = Date.now();

    expect(commitment.timestamp).toBeGreaterThanOrEqual(before);
    expect(commitment.timestamp).toBeLessThanOrEqual(after);
  });

  it('commit() sets scheme to sha256-commit', () => {
    const { commitment } = commit('test');
    expect(commitment.scheme).toBe('sha256-commit');
  });

  it('verifyCommitment() succeeds with correct opening', () => {
    const { commitment, opening } = commit('my-secret-value');
    expect(verifyCommitment(commitment, opening)).toBe(true);
  });

  it('verifyCommitment() fails with wrong value', () => {
    const { commitment, opening } = commit('correct');
    const wrongOpening = { ...opening, value: 'wrong' };
    expect(verifyCommitment(commitment, wrongOpening)).toBe(false);
  });

  it('verifyCommitment() fails with wrong blinding factor', () => {
    const { commitment, opening } = commit('secret');
    const wrongOpening = {
      ...opening,
      blindingFactor: generateBlindingFactor(),
    };
    expect(verifyCommitment(commitment, wrongOpening)).toBe(false);
  });

  it('verifyCommitment() fails with tampered hash', () => {
    const { commitment, opening } = commit('secret');
    const tampered = { ...commitment, hash: '0x' + 'ff'.repeat(32) };
    expect(verifyCommitment(tampered, opening)).toBe(false);
  });

  it('commit() returns opening with original value', () => {
    const { opening } = commit('hello-world');
    expect(opening.value).toBe('hello-world');
  });

  it('commit() returns 0x-prefixed blinding factor', () => {
    const { opening } = commit('test');
    expect(opening.blindingFactor).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// hashToHex
// ---------------------------------------------------------------------------

describe('hashToHex', () => {
  it('hashToHex() is deterministic', () => {
    const h1 = hashToHex('hello');
    const h2 = hashToHex('hello');
    expect(h1).toBe(h2);
  });

  it('hashToHex() returns 0x prefix', () => {
    const hash = hashToHex('test');
    expect(hash).toMatch(/^0x/);
  });

  it('hashToHex() returns 64 hex chars after 0x prefix', () => {
    const hash = hashToHex('anything');
    // 0x + 64 hex chars = 66 total
    expect(hash.length).toBe(66);
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('hashToHex() differs for different inputs', () => {
    const h1 = hashToHex('foo');
    const h2 = hashToHex('bar');
    expect(h1).not.toBe(h2);
  });
});

// ---------------------------------------------------------------------------
// generateBlindingFactor
// ---------------------------------------------------------------------------

describe('generateBlindingFactor', () => {
  it('returns 0x prefix + 64 hex chars', () => {
    const bf = generateBlindingFactor();
    expect(bf).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('generates unique values', () => {
    const factors = new Set<string>();
    for (let i = 0; i < 100; i++) {
      factors.add(generateBlindingFactor());
    }
    // All 100 should be unique (probability of collision is negligible)
    expect(factors.size).toBe(100);
  });
});
