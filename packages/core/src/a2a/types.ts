/**
 * A2A (Agent-to-Agent) Protocol — Type Definitions
 *
 * Defines the message format, endpoint discovery, and configuration
 * for secure agent-to-agent communication through the Chitin Shell pipeline.
 */

import type { AgentKeyPair } from '../intent/types.js';

/** An agent's A2A endpoint descriptor */
export interface A2AEndpoint {
  /** Agent's DID (e.g., did:chitin:<chainId>:<registry>:<agentId>) */
  did: string;
  /** HTTPS endpoint URL for receiving A2A messages */
  url: string;
  /** Ed25519 public key in hex encoding */
  publicKey: string;
  /** Supported message methods (e.g., 'invoke_tool', 'query') */
  capabilities: string[];
  /** Optional metadata about the agent */
  metadata?: Record<string, unknown>;
}

/** An A2A protocol message */
export interface A2AMessage {
  /** Unique message identifier (UUID v4) */
  id: string;
  /** Protocol version */
  version: 1;
  /** Message type */
  type: 'request' | 'response' | 'error' | 'notification';
  /** Sender DID */
  from: string;
  /** Recipient DID */
  to: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Message payload */
  payload: A2APayload;
  /** Ed25519 signature of the canonical message (hex) */
  signature: string;
  /** ID of the message being replied to */
  replyTo?: string;
  /** Time-to-live in seconds */
  ttl?: number;
}

/** The payload carried by an A2A message */
export interface A2APayload {
  /** Method name (e.g., 'invoke_tool', 'query', 'delegate', 'heartbeat') */
  method: string;
  /** Method parameters */
  params?: Record<string, unknown>;
  /** Result data (for responses) */
  result?: unknown;
  /** Error information */
  error?: { code: number; message: string; details?: unknown };
}

/** Configuration for an A2A client or server */
export interface A2AConfig {
  /** This agent's endpoint information */
  endpoint: A2AEndpoint;
  /** Key pair for signing messages */
  keyPair: AgentKeyPair;
  /** DIDs of trusted peers (empty array = trust no one, undefined = trust all verified) */
  trustedPeers?: string[];
  /** Max payload size in bytes (default: 1MB) */
  maxMessageSize?: number;
  /** Request timeout in ms (default: 30000) */
  timeout?: number;
  /** Retry count for failed requests (default: 0) */
  retries?: number;
  /** Rate limiting configuration */
  rateLimits?: {
    /** Max outgoing messages per minute */
    maxPerMinute: number;
    /** Max messages per peer per minute */
    maxPerPeer: number;
  };
}

/** Peer registry interface for endpoint discovery */
export interface A2ARegistry {
  /** Resolve a DID to its A2A endpoint */
  resolve(did: string): Promise<A2AEndpoint | null>;
  /** Register an agent's endpoint */
  register(endpoint: A2AEndpoint): Promise<void>;
  /** Remove an agent's endpoint */
  unregister(did: string): Promise<void>;
  /** List all registered endpoints */
  list(): Promise<A2AEndpoint[]>;
}

/** Runtime statistics for A2A communication */
export interface A2AStats {
  messagesSent: number;
  messagesReceived: number;
  errors: number;
  avgLatencyMs: number;
  activePeers: number;
}
