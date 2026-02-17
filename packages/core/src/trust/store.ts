/**
 * Trust Delegation — In-Memory Trust Store
 *
 * Default implementation of ITrustStore backed by a simple Map.
 * Suitable for testing and single-process environments.
 */

import type { DelegationToken, ITrustStore, TrustStoreEntry } from './types.js';

export class MemoryTrustStore implements ITrustStore {
  private entries: Map<string, TrustStoreEntry> = new Map();

  async store(token: DelegationToken): Promise<void> {
    this.entries.set(token.id, {
      token,
      revoked: false,
    });
  }

  async get(tokenId: string): Promise<TrustStoreEntry | null> {
    return this.entries.get(tokenId) ?? null;
  }

  async getByDelegate(delegateDid: string): Promise<TrustStoreEntry[]> {
    const results: TrustStoreEntry[] = [];
    for (const entry of this.entries.values()) {
      if (entry.token.delegate === delegateDid) {
        results.push(entry);
      }
    }
    return results;
  }

  async getByDelegator(delegatorDid: string): Promise<TrustStoreEntry[]> {
    const results: TrustStoreEntry[] = [];
    for (const entry of this.entries.values()) {
      if (entry.token.delegator === delegatorDid) {
        results.push(entry);
      }
    }
    return results;
  }

  async revoke(tokenId: string): Promise<void> {
    const entry = this.entries.get(tokenId);
    if (entry) {
      entry.revoked = true;
      entry.revokedAt = new Date().toISOString();
    }
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    const entry = this.entries.get(tokenId);
    if (!entry) return false;
    return entry.revoked;
  }
}
