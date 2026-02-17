/**
 * A2A Server — Processes incoming A2A messages
 *
 * Validates signatures, routes to registered handlers, and returns signed responses.
 */

import type { AgentKeyPair } from '../intent/types.js';
import type { A2AConfig, A2AMessage, A2APayload, A2ARegistry, A2AStats } from './types.js';
import {
  createA2AMessage,
  createErrorResponse,
  verifyA2AMessage,
  isMessageExpired,
} from './message.js';
import { MemoryA2ARegistry } from './registry.js';

/** Handler function for a specific A2A method */
export type A2AHandler = (message: A2AMessage) => Promise<A2APayload>;

export class A2AServer {
  private config: A2AConfig;
  private registry: A2ARegistry;
  private handlers: Map<string, A2AHandler> = new Map();
  private stats: A2AStats;

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

  /** Register a handler for a method */
  on(method: string, handler: A2AHandler): void {
    this.handlers.set(method, handler);
  }

  /** Remove a handler */
  off(method: string): void {
    this.handlers.delete(method);
  }

  /**
   * Process an incoming A2A message.
   * Validates, routes to the handler, and returns a signed response.
   */
  async handleMessage(
    rawMessage: A2AMessage,
    responseKeyPair?: AgentKeyPair,
  ): Promise<A2AMessage> {
    const kp = responseKeyPair ?? this.config.keyPair;
    this.stats.messagesReceived++;

    // 1. Validate the incoming message
    const validation = await this.validateIncoming(rawMessage);
    if (!validation.valid) {
      this.stats.errors++;
      return createErrorResponse(rawMessage, 400, validation.error!, kp);
    }

    // 2. Find handler for the method
    const handler = this.handlers.get(rawMessage.payload.method);
    if (!handler) {
      this.stats.errors++;
      return createErrorResponse(
        rawMessage,
        404,
        `Unknown method: ${rawMessage.payload.method}`,
        kp,
      );
    }

    // 3. Execute handler
    try {
      const start = Date.now();
      const resultPayload = await handler(rawMessage);
      const latency = Date.now() - start;

      this.updateStats(latency);

      const response = await createA2AMessage({
        type: 'response',
        from: this.config.endpoint.did,
        to: rawMessage.from,
        payload: resultPayload,
        keyPair: kp,
        replyTo: rawMessage.id,
      });

      this.stats.messagesSent++;
      return response;
    } catch {
      this.stats.errors++;
      return createErrorResponse(rawMessage, 500, 'Internal handler error', kp);
    }
  }

  /** Get current stats */
  getStats(): A2AStats {
    return { ...this.stats };
  }

  /** Get the underlying registry */
  getRegistry(): A2ARegistry {
    return this.registry;
  }

  // ---------------------------------------------------------------------------
  // Internal validation
  // ---------------------------------------------------------------------------

  private async validateIncoming(
    message: A2AMessage,
  ): Promise<{ valid: boolean; error?: string }> {
    // Check protocol version
    if (message.version !== 1) {
      return { valid: false, error: `Unsupported protocol version: ${message.version}` };
    }

    // Check message expiry
    if (isMessageExpired(message)) {
      return { valid: false, error: 'Message has expired' };
    }

    // Check message size
    const maxSize = this.config.maxMessageSize ?? 1_048_576;
    const size = JSON.stringify(message).length;
    if (size > maxSize) {
      return { valid: false, error: `Message too large (${size} > ${maxSize})` };
    }

    // Check trusted peers
    if (this.config.trustedPeers !== undefined) {
      if (!this.config.trustedPeers.includes(message.from)) {
        return { valid: false, error: `Untrusted peer: ${message.from}` };
      }
    }

    // Verify signature — look up sender's public key from registry
    const sender = await this.registry.resolve(message.from);
    if (!sender) {
      return { valid: false, error: `Unknown sender: ${message.from}` };
    }

    const verified = await verifyA2AMessage(message, sender.publicKey);
    if (!verified) {
      return { valid: false, error: 'Signature verification failed' };
    }

    return { valid: true };
  }

  private updateStats(latencyMs: number): void {
    const processed = this.stats.messagesReceived - this.stats.errors;
    if (processed <= 1) {
      this.stats.avgLatencyMs = latencyMs;
    } else {
      this.stats.avgLatencyMs =
        (this.stats.avgLatencyMs * (processed - 1) + latencyMs) / processed;
    }
  }
}
