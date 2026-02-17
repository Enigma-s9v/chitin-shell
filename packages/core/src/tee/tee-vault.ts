/**
 * TEE-backed Vault — Seals credentials using a TEE provider.
 *
 * All entries are encrypted at rest using TEE sealing.
 * The key material never leaves the TEE boundary.
 */

import type { IVault, VaultEntry } from '../proxy/types.js';
import type { ITeeProvider } from './types.js';

export class TeeVault implements IVault {
  private provider: ITeeProvider;
  private entries: Map<string, Buffer>; // Sealed entries

  constructor(provider: ITeeProvider) {
    this.provider = provider;
    this.entries = new Map();
  }

  async set(key: string, entry: Omit<VaultEntry, 'created_at'>): Promise<void> {
    const full: VaultEntry = {
      ...entry,
      created_at: new Date().toISOString(),
    };
    const json = JSON.stringify(full);
    const sealed = await this.provider.seal(Buffer.from(json, 'utf8'), key);
    this.entries.set(key, sealed);
  }

  async get(key: string): Promise<VaultEntry | null> {
    const sealed = this.entries.get(key);
    if (!sealed) return null;

    const plaintext = await this.provider.unseal(sealed, key);
    return JSON.parse(plaintext.toString('utf8')) as VaultEntry;
  }

  async delete(key: string): Promise<boolean> {
    return this.entries.delete(key);
  }

  async list(): Promise<string[]> {
    return Array.from(this.entries.keys());
  }

  async has(key: string): Promise<boolean> {
    return this.entries.has(key);
  }
}
