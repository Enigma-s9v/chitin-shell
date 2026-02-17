/**
 * A2A Message — Creation, canonicalization, signing, and verification
 *
 * Uses the same Ed25519 primitives as the Intent signer.
 */

import crypto from 'node:crypto';
import type { AgentKeyPair } from '../intent/types.js';
import type { A2AMessage, A2APayload } from './types.js';

// Ed25519 DER prefixes (same as intent/signer.ts)
const SPKI_ED25519_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const PKCS8_ED25519_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

/**
 * Create a canonical JSON string for signing.
 * Sorts keys recursively and excludes the `signature` field.
 */
export function canonicalizeMessage(msg: Omit<A2AMessage, 'signature'>): string {
  return JSON.stringify(sortKeys(msg));
}

/**
 * Create and sign a new A2A message.
 */
export async function createA2AMessage(params: {
  type: A2AMessage['type'];
  from: string;
  to: string;
  payload: A2APayload;
  keyPair: AgentKeyPair;
  replyTo?: string;
  ttl?: number;
}): Promise<A2AMessage> {
  const unsigned: Omit<A2AMessage, 'signature'> = {
    id: crypto.randomUUID(),
    version: 1,
    type: params.type,
    from: params.from,
    to: params.to,
    timestamp: new Date().toISOString(),
    payload: params.payload,
    ...(params.replyTo !== undefined ? { replyTo: params.replyTo } : {}),
    ...(params.ttl !== undefined ? { ttl: params.ttl } : {}),
  };

  const canonical = canonicalizeMessage(unsigned);
  const key = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, params.keyPair.privateKey]),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = crypto.sign(null, Buffer.from(canonical), key);

  return {
    ...unsigned,
    signature: sig.toString('hex'),
  };
}

/**
 * Verify the Ed25519 signature on an A2A message.
 * @param message - The full signed message
 * @param publicKey - Hex-encoded Ed25519 public key of the sender
 */
export async function verifyA2AMessage(
  message: A2AMessage,
  publicKey: string,
): Promise<boolean> {
  try {
    const { signature, ...unsigned } = message;
    const canonical = canonicalizeMessage(unsigned);
    const sigBuffer = Buffer.from(signature, 'hex');
    const pubKeyBytes = Buffer.from(publicKey, 'hex');
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, pubKeyBytes]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, Buffer.from(canonical), key, sigBuffer);
  } catch {
    return false;
  }
}

/**
 * Create an error response to a received message.
 */
export async function createErrorResponse(
  originalMessage: A2AMessage,
  code: number,
  errorMessage: string,
  keyPair: AgentKeyPair,
): Promise<A2AMessage> {
  return createA2AMessage({
    type: 'error',
    from: originalMessage.to,
    to: originalMessage.from,
    payload: {
      method: originalMessage.payload.method,
      error: { code, message: errorMessage },
    },
    keyPair,
    replyTo: originalMessage.id,
  });
}

/**
 * Check if a message has expired based on its timestamp + ttl.
 * Messages without a ttl never expire.
 */
export function isMessageExpired(message: A2AMessage): boolean {
  if (message.ttl === undefined) return false;
  const sent = new Date(message.timestamp).getTime();
  const now = Date.now();
  return now > sent + message.ttl * 1000;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
  }
  return sorted;
}
