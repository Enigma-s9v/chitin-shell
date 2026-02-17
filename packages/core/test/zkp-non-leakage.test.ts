import { describe, it, expect } from 'vitest';
import {
  quickLeakageCheck,
  generateNonLeakageProof,
  verifyNonLeakageProof,
} from '../src/zkp/non-leakage.js';

// ---------------------------------------------------------------------------
// Quick Leakage Check
// ---------------------------------------------------------------------------

describe('quickLeakageCheck', () => {
  it('detects plain secret in output', () => {
    const output = 'Here is the API key: sk-ant-abc123def456ghi789jkl0123';
    const vault = ['sk-ant-abc123def456ghi789jkl0123'];
    expect(quickLeakageCheck(output, vault)).toBe(true);
  });

  it('returns false for clean output', () => {
    const output = 'This is a safe response with no secrets.';
    const vault = ['supersecret123456789012345678'];
    expect(quickLeakageCheck(output, vault)).toBe(false);
  });

  it('handles empty vault', () => {
    expect(quickLeakageCheck('anything', [])).toBe(false);
  });

  it('handles empty output', () => {
    expect(quickLeakageCheck('', ['secret'])).toBe(false);
  });

  it('ignores empty vault entries', () => {
    expect(quickLeakageCheck('test', ['', ''])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Non-Leakage Proof Generation
// ---------------------------------------------------------------------------

describe('generateNonLeakageProof', () => {
  it('creates valid proof for clean output', () => {
    const output = 'This output is perfectly clean and contains no secrets whatsoever.';
    const vault = ['my-super-secret-key-12345678'];
    const proof = generateNonLeakageProof(output, vault);

    expect(proof.verified).toBe(true);
    expect(proof.outputHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.exclusionRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.vaultEntryCount).toBe(1);
    expect(proof.scheme).toBe('sha256-commit');
    expect(typeof proof.timestamp).toBe('number');
  });

  it('marks verified=false when secret found', () => {
    const secret = 'this-is-a-vault-secret-value';
    const output = `Response: ${secret} was leaked!`;
    const vault = [secret];
    const proof = generateNonLeakageProof(output, vault);

    expect(proof.verified).toBe(false);
  });

  it('handles empty output', () => {
    const proof = generateNonLeakageProof('', ['secret']);
    expect(proof.verified).toBe(true);
    expect(proof.outputHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('handles empty vault', () => {
    const proof = generateNonLeakageProof('some output', []);
    expect(proof.verified).toBe(true);
    expect(proof.vaultEntryCount).toBe(0);
  });

  it('handles very long output efficiently', () => {
    // 10KB output with small window sizes should still be fast
    const output = 'a'.repeat(10_000);
    const vault = ['not-in-output-at-all-xxxx'];
    const start = Date.now();
    const proof = generateNonLeakageProof(output, vault, [16, 24]);
    const elapsed = Date.now() - start;

    expect(proof.verified).toBe(true);
    // Should complete in under 5 seconds
    expect(elapsed).toBeLessThan(5000);
  });
});

// ---------------------------------------------------------------------------
// Non-Leakage Proof Verification
// ---------------------------------------------------------------------------

describe('verifyNonLeakageProof', () => {
  it('succeeds for genuine clean output', () => {
    const output = 'Clean output with no secrets inside it.';
    const vault = ['supersecretvalue1234567890123'];
    const proof = generateNonLeakageProof(output, vault);

    expect(verifyNonLeakageProof(proof, output, vault)).toBe(true);
  });

  it('fails when output modified after proof', () => {
    const output = 'Original clean output text here.';
    const vault = ['notsecret1234567890123456789'];
    const proof = generateNonLeakageProof(output, vault);

    const modified = 'MODIFIED output text here.';
    expect(verifyNonLeakageProof(proof, modified, vault)).toBe(false);
  });

  it('fails when vault entries modified after proof', () => {
    const output = 'Clean output for this test case.';
    const vault = ['original-secret-12345678901'];
    const proof = generateNonLeakageProof(output, vault);

    const modifiedVault = ['different-secret-1234567890'];
    expect(verifyNonLeakageProof(proof, output, modifiedVault)).toBe(false);
  });

  it('fails when vault entry count changes', () => {
    const output = 'Clean output text for testing.';
    const vault = ['secret-one-1234567890123456'];
    const proof = generateNonLeakageProof(output, vault);

    const extraVault = ['secret-one-1234567890123456', 'secret-two-123456789012345'];
    expect(verifyNonLeakageProof(proof, output, extraVault)).toBe(false);
  });

  it('verifies proof with leaked secret correctly', () => {
    const secret = 'leaked-secret-value-here!';
    const output = `Oops: ${secret}`;
    const vault = [secret];
    const proof = generateNonLeakageProof(output, vault);

    // The proof should verify (consistent) even though verified=false
    expect(proof.verified).toBe(false);
    expect(verifyNonLeakageProof(proof, output, vault)).toBe(true);
  });
});
