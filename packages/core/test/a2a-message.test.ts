import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  canonicalizeMessage,
  createA2AMessage,
  verifyA2AMessage,
  createErrorResponse,
  isMessageExpired,
} from '../src/a2a/message.js';
import { generateKeyPair } from '../src/intent/signer.js';
import type { A2AMessage } from '../src/a2a/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeyPair() {
  return generateKeyPair();
}

function publicKeyHex(kp: ReturnType<typeof generateKeyPair>): string {
  return Buffer.from(kp.publicKey).toString('hex');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('canonicalizeMessage', () => {
  it('is deterministic — same input always yields same output', () => {
    const msg = {
      id: 'test-id',
      version: 1 as const,
      type: 'request' as const,
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      timestamp: '2026-02-17T00:00:00.000Z',
      payload: { method: 'query', params: { b: 2, a: 1 } },
    };

    const a = canonicalizeMessage(msg);
    const b = canonicalizeMessage(msg);
    expect(a).toBe(b);
  });

  it('sorts keys recursively', () => {
    const msg = {
      version: 1 as const,
      id: 'test-id',
      type: 'request' as const,
      to: 'did:chitin:1:0x5678:2',
      from: 'did:chitin:1:0x1234:1',
      timestamp: '2026-02-17T00:00:00.000Z',
      payload: { params: { z: 1, a: 2 }, method: 'query' },
    };

    const canonical = canonicalizeMessage(msg);
    const parsed = JSON.parse(canonical);
    const keys = Object.keys(parsed);

    // Keys should be sorted alphabetically
    expect(keys).toEqual([...keys].sort());

    // Nested keys in payload should also be sorted
    const payloadKeys = Object.keys(parsed.payload);
    expect(payloadKeys).toEqual([...payloadKeys].sort());
  });

  it('excludes signature field (since input is Omit<A2AMessage, "signature">)', () => {
    const msg = {
      id: 'test-id',
      version: 1 as const,
      type: 'request' as const,
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      timestamp: '2026-02-17T00:00:00.000Z',
      payload: { method: 'query' },
    };

    const canonical = canonicalizeMessage(msg);
    expect(canonical).not.toContain('signature');
  });
});

describe('createA2AMessage', () => {
  it('creates a valid message with all required fields', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query', params: { foo: 'bar' } },
      keyPair: kp,
    });

    expect(msg.id).toBeTruthy();
    expect(msg.version).toBe(1);
    expect(msg.type).toBe('request');
    expect(msg.from).toBe('did:chitin:1:0x1234:1');
    expect(msg.to).toBe('did:chitin:1:0x5678:2');
    expect(msg.timestamp).toBeTruthy();
    expect(msg.payload.method).toBe('query');
    expect(msg.payload.params).toEqual({ foo: 'bar' });
    expect(msg.signature).toBeTruthy();
    expect(msg.signature).toMatch(/^[0-9a-f]+$/);
  });

  it('generates unique IDs for each message', async () => {
    const kp = makeKeyPair();
    const params = {
      type: 'request' as const,
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp,
    };

    const msg1 = await createA2AMessage(params);
    const msg2 = await createA2AMessage(params);

    expect(msg1.id).not.toBe(msg2.id);
  });

  it('signs the message with Ed25519', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'heartbeat' },
      keyPair: kp,
    });

    // Signature should be a valid hex string (Ed25519 signatures are 64 bytes = 128 hex chars)
    expect(msg.signature).toMatch(/^[0-9a-f]{128}$/);
  });

  it('includes replyTo field when provided', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'response',
      from: 'did:chitin:1:0x5678:2',
      to: 'did:chitin:1:0x1234:1',
      payload: { method: 'query', result: { data: 'ok' } },
      keyPair: kp,
      replyTo: 'original-msg-id',
    });

    expect(msg.replyTo).toBe('original-msg-id');
  });

  it('includes ttl field when provided', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp,
      ttl: 60,
    });

    expect(msg.ttl).toBe(60);
  });
});

describe('verifyA2AMessage', () => {
  it('succeeds for a valid message', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp,
    });

    const valid = await verifyA2AMessage(msg, publicKeyHex(kp));
    expect(valid).toBe(true);
  });

  it('fails for a tampered payload', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query', params: { secret: 'value' } },
      keyPair: kp,
    });

    // Tamper with payload
    msg.payload.params = { secret: 'tampered' };

    const valid = await verifyA2AMessage(msg, publicKeyHex(kp));
    expect(valid).toBe(false);
  });

  it('fails with wrong public key', async () => {
    const kp1 = makeKeyPair();
    const kp2 = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp1,
    });

    // Verify with a different key
    const valid = await verifyA2AMessage(msg, publicKeyHex(kp2));
    expect(valid).toBe(false);
  });

  it('returns false for malformed signature', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp,
    });

    // Replace with garbage signature
    msg.signature = 'not-a-valid-hex-signature';

    const valid = await verifyA2AMessage(msg, publicKeyHex(kp));
    expect(valid).toBe(false);
  });
});

describe('createErrorResponse', () => {
  it('creates a proper error response', async () => {
    const kpSender = makeKeyPair();
    const kpReceiver = makeKeyPair();

    const original = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'invoke_tool', params: { tool: 'test' } },
      keyPair: kpSender,
    });

    const errMsg = await createErrorResponse(original, 404, 'Tool not found', kpReceiver);

    expect(errMsg.type).toBe('error');
    expect(errMsg.from).toBe('did:chitin:1:0x5678:2');
    expect(errMsg.to).toBe('did:chitin:1:0x1234:1');
    expect(errMsg.replyTo).toBe(original.id);
    expect(errMsg.payload.method).toBe('invoke_tool');
    expect(errMsg.payload.error).toEqual({
      code: 404,
      message: 'Tool not found',
    });
    expect(errMsg.signature).toBeTruthy();
  });
});

describe('isMessageExpired', () => {
  it('returns false for a fresh message', async () => {
    const kp = makeKeyPair();

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kp,
      ttl: 3600, // 1 hour
    });

    expect(isMessageExpired(msg)).toBe(false);
  });

  it('returns true for an expired message', () => {
    const expired: A2AMessage = {
      id: 'expired-msg',
      version: 1,
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      timestamp: new Date(Date.now() - 120_000).toISOString(), // 2 minutes ago
      payload: { method: 'query' },
      signature: 'deadbeef',
      ttl: 60, // 60 seconds — already expired
    };

    expect(isMessageExpired(expired)).toBe(true);
  });

  it('returns false when no ttl is set', () => {
    const msg: A2AMessage = {
      id: 'no-ttl-msg',
      version: 1,
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      timestamp: new Date(Date.now() - 86400_000).toISOString(), // 24 hours ago
      payload: { method: 'query' },
      signature: 'deadbeef',
      // no ttl — never expires
    };

    expect(isMessageExpired(msg)).toBe(false);
  });
});
