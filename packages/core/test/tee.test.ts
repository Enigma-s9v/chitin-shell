import { describe, it, expect, beforeEach } from 'vitest';
import { MockTeeProvider } from '../src/tee/mock-provider.js';
import { TeeVault } from '../src/tee/tee-vault.js';
import type { TeeAttestation } from '../src/tee/types.js';

// ---------------------------------------------------------------------------
// MockTeeProvider
// ---------------------------------------------------------------------------
describe('MockTeeProvider', () => {
  let provider: MockTeeProvider;

  beforeEach(() => {
    provider = new MockTeeProvider();
  });

  it('getCapabilities returns correct values', async () => {
    const caps = await provider.getCapabilities();

    expect(caps.provider).toBe('mock');
    expect(caps.available).toBe(true);
    expect(caps.sealingSupported).toBe(true);
    expect(caps.attestationSupported).toBe(true);
    expect(caps.secureMemory).toBe(false);
    expect(caps.maxMemoryMb).toBe(256);
  });

  it('attest creates valid attestation', async () => {
    const attestation = await provider.attest();

    expect(attestation.provider).toBe('mock');
    expect(attestation.quote).toBeTruthy();
    expect(attestation.timestamp).toBeTruthy();
    expect(attestation.measurements).toHaveLength(1);
    expect(attestation.measurements[0].name).toBe('code_hash');
    expect(attestation.measurements[0].algorithm).toBe('sha256');
    expect(attestation.signature).toBeTruthy();
  });

  it('attest includes userData in measurement', async () => {
    const a1 = await provider.attest('hello-world');
    const a2 = await provider.attest('different-data');

    // Different userData should produce different measurements
    expect(a1.measurements[0].value).not.toBe(a2.measurements[0].value);
    // But both should be valid hex
    expect(a1.measurements[0].value).toMatch(/^[0-9a-f]{64}$/);
    expect(a2.measurements[0].value).toMatch(/^[0-9a-f]{64}$/);
  });

  it('verifyAttestation succeeds for own attestation', async () => {
    const attestation = await provider.attest('test-data');
    const isValid = await provider.verifyAttestation(attestation);

    expect(isValid).toBe(true);
  });

  it('verifyAttestation fails for tampered quote', async () => {
    const attestation = await provider.attest('test-data');
    const tampered: TeeAttestation = {
      ...attestation,
      quote: Buffer.from('tampered-quote').toString('base64'),
    };
    const isValid = await provider.verifyAttestation(tampered);

    expect(isValid).toBe(false);
  });

  it('verifyAttestation fails for wrong provider', async () => {
    const attestation = await provider.attest('test-data');
    const wrongProvider: TeeAttestation = {
      ...attestation,
      provider: 'sgx',
    };
    const isValid = await provider.verifyAttestation(wrongProvider);

    expect(isValid).toBe(false);
  });

  it('seal encrypts data', async () => {
    const plaintext = Buffer.from('secret-credentials');
    const sealed = await provider.seal(plaintext);

    // Sealed data should be different from plaintext
    expect(sealed.equals(plaintext)).toBe(false);
    // Sealed must have at least IV (12) + authTag (16) + some ciphertext
    expect(sealed.length).toBeGreaterThan(28);
  });

  it('unseal recovers original data', async () => {
    const plaintext = Buffer.from('my-api-key-12345');
    const sealed = await provider.seal(plaintext);
    const unsealed = await provider.unseal(sealed);

    expect(unsealed.toString('utf8')).toBe('my-api-key-12345');
  });

  it('seal + unseal round-trip', async () => {
    const data = Buffer.from(JSON.stringify({ key: 'value', number: 42 }));
    const sealed = await provider.seal(data);
    const unsealed = await provider.unseal(sealed);

    expect(unsealed.equals(data)).toBe(true);
  });

  it('unseal fails with wrong key (different provider instance)', async () => {
    const provider1 = new MockTeeProvider();
    const provider2 = new MockTeeProvider();

    const plaintext = Buffer.from('secret-data');
    const sealed = await provider1.seal(plaintext);

    // Different provider has a different sealKey
    await expect(provider2.unseal(sealed)).rejects.toThrow();
  });

  it('seal with label, unseal with same label works', async () => {
    const plaintext = Buffer.from('labeled-secret');
    const sealed = await provider.seal(plaintext, 'my-label');
    const unsealed = await provider.unseal(sealed, 'my-label');

    expect(unsealed.toString('utf8')).toBe('labeled-secret');
  });

  it('seal with label, unseal with wrong label fails', async () => {
    const plaintext = Buffer.from('labeled-secret');
    const sealed = await provider.seal(plaintext, 'correct-label');

    await expect(provider.unseal(sealed, 'wrong-label')).rejects.toThrow();
  });

  it('measure returns sha256', async () => {
    const measurement = await provider.measure('function hello() { return "world"; }');

    expect(measurement.name).toBe('code_hash');
    expect(measurement.algorithm).toBe('sha256');
    expect(measurement.value).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// TeeVault
// ---------------------------------------------------------------------------
describe('TeeVault', () => {
  let vault: TeeVault;
  let provider: MockTeeProvider;

  beforeEach(() => {
    provider = new MockTeeProvider();
    vault = new TeeVault(provider);
  });

  it('set + get round-trip', async () => {
    await vault.set('openai', { type: 'api_key', value: 'sk-test-123' });
    const entry = await vault.get('openai');

    expect(entry).not.toBeNull();
    expect(entry!.type).toBe('api_key');
    expect(entry!.value).toBe('sk-test-123');
    expect(entry!.created_at).toBeTruthy();
  });

  it('set overwrites existing', async () => {
    await vault.set('key', { type: 'api_key', value: 'old-value' });
    await vault.set('key', { type: 'api_key', value: 'new-value' });
    const entry = await vault.get('key');

    expect(entry!.value).toBe('new-value');
  });

  it('delete removes entry', async () => {
    await vault.set('temp', { type: 'bearer', value: 'abc' });
    const deleted = await vault.delete('temp');

    expect(deleted).toBe(true);
    expect(await vault.get('temp')).toBeNull();
  });

  it('list returns all keys', async () => {
    await vault.set('a', { type: 'api_key', value: '1' });
    await vault.set('b', { type: 'api_key', value: '2' });
    await vault.set('c', { type: 'bearer', value: '3' });

    const keys = await vault.list();
    expect(keys).toHaveLength(3);
    expect(keys).toContain('a');
    expect(keys).toContain('b');
    expect(keys).toContain('c');
  });

  it('has returns true for existing key', async () => {
    await vault.set('exists', { type: 'custom', value: 'v' });
    expect(await vault.has('exists')).toBe(true);
  });

  it('has returns false for missing key', async () => {
    expect(await vault.has('nope')).toBe(false);
  });

  it('get returns null for missing key', async () => {
    const entry = await vault.get('nonexistent');
    expect(entry).toBeNull();
  });

  it('entries are sealed (raw Map values are not readable JSON)', async () => {
    await vault.set('secret', { type: 'api_key', value: 'sk-secret-value' });

    // Access the internal entries map via any-cast
    const entries = (vault as unknown as { entries: Map<string, Buffer> }).entries;
    const rawSealed = entries.get('secret');

    expect(rawSealed).toBeDefined();
    // The raw buffer should NOT be parseable as JSON containing the secret
    const rawStr = rawSealed!.toString('utf8');
    expect(rawStr).not.toContain('sk-secret-value');

    // But getting via the vault API should work
    const entry = await vault.get('secret');
    expect(entry!.value).toBe('sk-secret-value');
  });
});
