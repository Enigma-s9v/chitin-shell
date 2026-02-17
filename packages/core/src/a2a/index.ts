/**
 * A2A (Agent-to-Agent) Protocol — Barrel exports
 */

// Types
export type {
  A2AEndpoint,
  A2AMessage,
  A2APayload,
  A2AConfig,
  A2ARegistry,
  A2AStats,
} from './types.js';

// Registry
export { MemoryA2ARegistry } from './registry.js';

// Message
export {
  canonicalizeMessage,
  createA2AMessage,
  verifyA2AMessage,
  createErrorResponse,
  isMessageExpired,
} from './message.js';

// Client
export { A2AClient } from './client.js';

// Server
export { A2AServer } from './server.js';
export type { A2AHandler } from './server.js';

// Middleware
export { createA2AMapper, createSecureA2AHandler } from './middleware.js';
