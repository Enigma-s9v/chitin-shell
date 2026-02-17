/**
 * A2A Registry — In-memory peer endpoint registry
 */

import type { A2AEndpoint, A2ARegistry } from './types.js';

export class MemoryA2ARegistry implements A2ARegistry {
  private peers: Map<string, A2AEndpoint> = new Map();

  async resolve(did: string): Promise<A2AEndpoint | null> {
    return this.peers.get(did) ?? null;
  }

  async register(endpoint: A2AEndpoint): Promise<void> {
    this.peers.set(endpoint.did, endpoint);
  }

  async unregister(did: string): Promise<void> {
    this.peers.delete(did);
  }

  async list(): Promise<A2AEndpoint[]> {
    return Array.from(this.peers.values());
  }
}
