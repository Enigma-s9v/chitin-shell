/**
 * A2A Client — Sends messages to remote agents over HTTPS
 *
 * Uses globalThis.fetch (Node.js 20+ built-in) for HTTP transport.
 */

import type { AgentKeyPair } from '../intent/types.js';
import type { A2AConfig, A2AEndpoint, A2AMessage, A2ARegistry, A2AStats } from './types.js';
import { createA2AMessage, verifyA2AMessage, isMessageExpired } from './message.js';
import { MemoryA2ARegistry } from './registry.js';

const DEFAULT_TIMEOUT = 30_000;
const DEFAULT_MAX_MESSAGE_SIZE = 1_048_576; // 1MB

export class A2AClient {
  private config: A2AConfig;
  private registry: A2ARegistry;
  private stats: A2AStats;
  private rateLimiter: Map<string, number[]> = new Map();

  constructor(config: A2AConfig, registry?: A2ARegistry) {
    this.config = config;
    this.registry = registry ?? new MemoryA2ARegistry();
    this.stats = {
      messagesSent: 0,
      messagesReceived: 0,
      errors: 0,
      avgLatencyMs: 0,
      activePeers: 0,
    };
  }

  /**
   * Send a request to another agent and wait for the response.
   */
  async request(
    toDid: string,
    method: string,
    params?: Record<string, unknown>,
    keyPair?: AgentKeyPair,
  ): Promise<A2AMessage> {
    const kp = keyPair ?? this.config.keyPair;
    const endpoint = await this.resolveEndpoint(toDid);

    if (!this.checkRateLimit(toDid)) {
      throw new Error(`Rate limit exceeded for peer: ${toDid}`);
    }

    const message = await createA2AMessage({
      type: 'request',
      from: this.config.endpoint.did,
      to: toDid,
      payload: { method, params },
      keyPair: kp,
    });

    const response = await this.sendMessage(endpoint, message);
    if (!response) {
      throw new Error(`No response from peer: ${toDid}`);
    }

    return response;
  }

  /**
   * Send a notification (fire-and-forget, no response expected).
   */
  async notify(
    toDid: string,
    method: string,
    params?: Record<string, unknown>,
    keyPair?: AgentKeyPair,
  ): Promise<void> {
    const kp = keyPair ?? this.config.keyPair;
    const endpoint = await this.resolveEndpoint(toDid);

    if (!this.checkRateLimit(toDid)) {
      throw new Error(`Rate limit exceeded for peer: ${toDid}`);
    }

    const message = await createA2AMessage({
      type: 'notification',
      from: this.config.endpoint.did,
      to: toDid,
      payload: { method, params },
      keyPair: kp,
    });

    await this.sendMessage(endpoint, message);
  }

  /** Get current A2A stats */
  getStats(): A2AStats {
    return { ...this.stats };
  }

  /** Get the underlying registry */
  getRegistry(): A2ARegistry {
    return this.registry;
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  private async resolveEndpoint(did: string): Promise<A2AEndpoint> {
    const endpoint = await this.registry.resolve(did);
    if (!endpoint) {
      throw new Error(`Unknown peer: ${did}. Register endpoint first.`);
    }
    return endpoint;
  }

  private async sendMessage(
    endpoint: A2AEndpoint,
    message: A2AMessage,
  ): Promise<A2AMessage | null> {
    const body = JSON.stringify(message);
    const maxSize = this.config.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE;
    if (body.length > maxSize) {
      throw new Error(`Message exceeds max size (${body.length} > ${maxSize})`);
    }

    const timeout = this.config.timeout ?? DEFAULT_TIMEOUT;
    const start = Date.now();
    let lastError: Error | undefined;
    const maxAttempts = 1 + (this.config.retries ?? 0);

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);

        const response = await globalThis.fetch(endpoint.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          signal: controller.signal,
        });

        clearTimeout(timer);

        const latency = Date.now() - start;
        this.updateStats(latency);

        if (!response.ok) {
          this.stats.errors++;
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        // Notifications may not return a body
        if (message.type === 'notification') {
          return null;
        }

        const responseMessage = (await response.json()) as A2AMessage;

        // Verify response signature if we have the peer's public key
        const verified = await verifyA2AMessage(responseMessage, endpoint.publicKey);
        if (!verified) {
          this.stats.errors++;
          throw new Error('Response signature verification failed');
        }

        if (isMessageExpired(responseMessage)) {
          this.stats.errors++;
          throw new Error('Response message has expired');
        }

        this.stats.messagesReceived++;
        return responseMessage;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt === maxAttempts - 1) break;
      }
    }

    this.stats.errors++;
    throw lastError ?? new Error('Send failed');
  }

  private checkRateLimit(peerDid: string): boolean {
    const limits = this.config.rateLimits;
    if (!limits) return true;

    const now = Date.now();
    const windowMs = 60_000; // 1 minute

    // Global rate limit
    const allTimestamps = Array.from(this.rateLimiter.values()).flat();
    const recentGlobal = allTimestamps.filter((t) => now - t < windowMs);
    if (recentGlobal.length >= limits.maxPerMinute) return false;

    // Per-peer rate limit
    const peerTimestamps = this.rateLimiter.get(peerDid) ?? [];
    const recentPeer = peerTimestamps.filter((t) => now - t < windowMs);
    if (recentPeer.length >= limits.maxPerPeer) return false;

    // Record this request
    recentPeer.push(now);
    this.rateLimiter.set(peerDid, recentPeer);

    return true;
  }

  private updateStats(latencyMs: number): void {
    this.stats.messagesSent++;
    const total = this.stats.messagesSent;
    this.stats.avgLatencyMs =
      (this.stats.avgLatencyMs * (total - 1) + latencyMs) / total;
    // Count unique peers we've communicated with
    this.stats.activePeers = this.rateLimiter.size;
  }
}
