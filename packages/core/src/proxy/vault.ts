import type { IVault, VaultEntry } from './types.js';

export class MemoryVault implements IVault {
  private store = new Map<string, VaultEntry>();

  async get(key: string): Promise<VaultEntry | null> {
    return this.store.get(key) ?? null;
  }

  async set(key: string, entry: Omit<VaultEntry, 'created_at'>): Promise<void> {
    this.store.set(key, {
      ...entry,
      created_at: new Date().toISOString(),
    });
  }

  async delete(key: string): Promise<boolean> {
    return this.store.delete(key);
  }

  async list(): Promise<string[]> {
    return Array.from(this.store.keys());
  }

  async has(key: string): Promise<boolean> {
    return this.store.has(key);
  }
}
