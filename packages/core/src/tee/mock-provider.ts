/**
 * Mock TEE Provider — Development & Testing
 *
 * Uses node:crypto to simulate TEE sealing (AES-256-GCM) and attestation.
 * NOT for production use — real TEE providers should be used in production.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import type {
  ITeeProvider,
  TeeAttestation,
  TeeCapabilities,
  TeeMeasurement,
} from './types.js';

export class MockTeeProvider implements ITeeProvider {
  private sealKey: Buffer;

  constructor() {
    // Random 256-bit key, unique per instance — simulates TEE-bound key
    this.sealKey = randomBytes(32);
  }

  async getCapabilities(): Promise<TeeCapabilities> {
    return {
      provider: 'mock',
      available: true,
      sealingSupported: true,
      attestationSupported: true,
      secureMemory: false,
      maxMemoryMb: 256,
    };
  }

  async attest(userData?: string): Promise<TeeAttestation> {
    const nonce = randomBytes(16).toString('hex');
    const quote = Buffer.from(`mock-attestation-${nonce}`).toString('base64');

    const measurementInput = userData ?? 'no-data';
    const measurementValue = createHash('sha256').update(measurementInput).digest('hex');

    const signature = createHash('sha256').update(quote).digest('hex');

    return {
      provider: 'mock',
      quote,
      timestamp: new Date().toISOString(),
      measurements: [
        {
          name: 'code_hash',
          value: measurementValue,
          algorithm: 'sha256',
        },
      ],
      signature,
    };
  }

  async verifyAttestation(attestation: TeeAttestation): Promise<boolean> {
    // Verify provider
    if (attestation.provider !== 'mock') {
      return false;
    }

    // Verify signature matches sha256 of quote
    const expectedSignature = createHash('sha256').update(attestation.quote).digest('hex');
    return attestation.signature === expectedSignature;
  }

  async seal(data: Buffer, label?: string): Promise<Buffer> {
    const iv = randomBytes(12); // 12-byte IV for AES-256-GCM
    const cipher = createCipheriv('aes-256-gcm', this.sealKey, iv);

    // Use label as AAD (Additional Authenticated Data) if provided
    if (label) {
      cipher.setAAD(Buffer.from(label, 'utf8'));
    }

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag(); // 16 bytes

    // Format: [12-byte IV][16-byte authTag][ciphertext]
    return Buffer.concat([iv, authTag, encrypted]);
  }

  async unseal(sealed: Buffer, label?: string): Promise<Buffer> {
    if (sealed.length < 28) {
      throw new Error('Invalid sealed data: too short');
    }

    const iv = sealed.subarray(0, 12);
    const authTag = sealed.subarray(12, 28);
    const ciphertext = sealed.subarray(28);

    const decipher = createDecipheriv('aes-256-gcm', this.sealKey, iv);
    decipher.setAuthTag(authTag);

    // Use label as AAD if provided
    if (label) {
      decipher.setAAD(Buffer.from(label, 'utf8'));
    }

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  async measure(code: string | Buffer): Promise<TeeMeasurement> {
    const input = typeof code === 'string' ? code : code;
    const value = createHash('sha256').update(input).digest('hex');

    return {
      name: 'code_hash',
      value,
      algorithm: 'sha256',
    };
  }
}
