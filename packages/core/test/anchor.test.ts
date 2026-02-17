import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuditAnchor } from '../src/audit/anchor.js';
import { AnchoredAuditLogger } from '../src/audit/anchored-logger.js';
import type { AuditEntry } from '../src/audit/types.js';
import type { AnchorConfig } from '../src/audit/anchor.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: 'entry-001',
    timestamp: '2026-02-17T00:00:00.000Z',
    intent_id: 'intent-001',
    agent_did: 'did:chitin:test-agent',
    action_type: 'send_message',
    tier: 1,
    decision: 'approved',
    reason: 'Policy allows tier 1 actions',
    ...overrides,
  };
}

function makeEntries(count: number): AuditEntry[] {
  return Array.from({ length: count }, (_, i) =>
    makeEntry({
      id: `entry-${String(i + 1).padStart(3, '0')}`,
      timestamp: new Date(Date.UTC(2026, 1, 17, 0, 0, i)).toISOString(),
      intent_id: `intent-${String(i + 1).padStart(3, '0')}`,
    }),
  );
}

const TEST_TX_HASH =
  '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

const defaultConfig: AnchorConfig = {
  rpcUrl: 'https://rpc.example.com',
  contractAddress: '0x1234567890abcdef1234567890abcdef12345678',
  chainId: 84532,
  signerPrivateKey: '0x' + 'aa'.repeat(32),
  agentDid: 'did:chitin:test-agent',
  batchSize: 100,
};

// ---------------------------------------------------------------------------
// Mock fetch globally
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof fetch>();

beforeEach(() => {
  mockFetch.mockReset();
  // Default: return a fresh Response each call (Response body can only be read once)
  mockFetch.mockImplementation(async () =>
    new Response(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: TEST_TX_HASH }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  );
  vi.stubGlobal('fetch', mockFetch);
});

// ---------------------------------------------------------------------------
// AuditAnchor
// ---------------------------------------------------------------------------

describe('AuditAnchor', () => {
  it('addEntries accumulates pending entries', () => {
    const anchor = new AuditAnchor(defaultConfig);
    expect(anchor.getPendingCount()).toBe(0);

    anchor.addEntries(makeEntries(3));
    expect(anchor.getPendingCount()).toBe(3);

    anchor.addEntries(makeEntries(2));
    expect(anchor.getPendingCount()).toBe(5);
  });

  it('anchor() returns null when no pending entries', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    const result = await anchor.anchor();
    expect(result).toBeNull();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('anchor() commits batch and returns AnchorResult', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    const entries = makeEntries(4);
    anchor.addEntries(entries);

    const result = await anchor.anchor();

    expect(result).not.toBeNull();
    expect(result!.commitmentId).toBe(1);
    expect(result!.merkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result!.entryCount).toBe(4);
    expect(result!.txHash).toBe(TEST_TX_HASH);
    expect(result!.fromTimestamp).toBeTruthy();
    expect(result!.toTimestamp).toBeTruthy();

    // Pending should be cleared
    expect(anchor.getPendingCount()).toBe(0);

    // fetch should have been called once
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('getPendingCount tracks correctly after anchor', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    anchor.addEntries(makeEntries(5));
    expect(anchor.getPendingCount()).toBe(5);

    await anchor.anchor();
    expect(anchor.getPendingCount()).toBe(0);

    anchor.addEntries(makeEntries(2));
    expect(anchor.getPendingCount()).toBe(2);
  });

  it('getAnchors returns history', async () => {
    const anchor = new AuditAnchor(defaultConfig);

    anchor.addEntries(makeEntries(3));
    await anchor.anchor();

    anchor.addEntries(makeEntries(2));
    await anchor.anchor();

    const anchors = anchor.getAnchors();
    expect(anchors).toHaveLength(2);
    expect(anchors[0].commitmentId).toBe(1);
    expect(anchors[1].commitmentId).toBe(2);
    expect(anchors[0].entryCount).toBe(3);
    expect(anchors[1].entryCount).toBe(2);
  });

  it('generateProof returns valid proof', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    anchor.addEntries(makeEntries(4));
    const result = await anchor.anchor();

    const proof = anchor.generateProof(result!.commitmentId, 0);
    expect(proof).not.toBeNull();
    expect(proof!.commitmentId).toBe(result!.commitmentId);
    expect(proof!.merkleRoot).toBe(result!.merkleRoot);
    expect(proof!.leaf).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof!.proof.length).toBeGreaterThan(0);
    expect(proof!.index).toBe(0);
    expect(proof!.verified).toBe(false);
  });

  it('generateProof returns null for unknown commitmentId', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    anchor.addEntries(makeEntries(4));
    await anchor.anchor();

    const proof = anchor.generateProof(999, 0);
    expect(proof).toBeNull();
  });

  it('generateProof returns null for out-of-range entryIndex', async () => {
    const anchor = new AuditAnchor(defaultConfig);
    anchor.addEntries(makeEntries(4));
    const result = await anchor.anchor();

    expect(anchor.generateProof(result!.commitmentId, 10)).toBeNull();
    expect(anchor.generateProof(result!.commitmentId, -1)).toBeNull();
  });

  it('increments commitmentId across multiple anchors', async () => {
    const anchor = new AuditAnchor(defaultConfig);

    anchor.addEntries(makeEntries(1));
    const r1 = await anchor.anchor();

    anchor.addEntries(makeEntries(1));
    const r2 = await anchor.anchor();

    anchor.addEntries(makeEntries(1));
    const r3 = await anchor.anchor();

    expect(r1!.commitmentId).toBe(1);
    expect(r2!.commitmentId).toBe(2);
    expect(r3!.commitmentId).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// AnchoredAuditLogger
// ---------------------------------------------------------------------------

describe('AnchoredAuditLogger', () => {
  // Mock filesystem for LocalAuditLogger
  vi.mock('node:fs/promises', () => ({
    mkdir: vi.fn().mockResolvedValue(undefined),
    appendFile: vi.fn().mockResolvedValue(undefined),
  }));

  it('logs locally and accumulates for anchor', async () => {
    const logger = new AnchoredAuditLogger(defaultConfig);

    const entry = await logger.log({
      intent_id: 'intent-001',
      agent_did: 'did:chitin:test',
      action_type: 'send_message',
      tier: 1,
      decision: 'approved',
      reason: 'test',
    });

    expect(entry.id).toBeTruthy();
    expect(entry.timestamp).toBeTruthy();
    expect(logger.getPendingCount()).toBe(1);
    expect(logger.getAnchors()).toHaveLength(0);
  });

  it('auto-triggers anchor at batchSize', async () => {
    const config: AnchorConfig = { ...defaultConfig, batchSize: 3 };
    const logger = new AnchoredAuditLogger(config);

    // Log 2 entries — should not trigger anchor yet
    for (let i = 0; i < 2; i++) {
      await logger.log({
        intent_id: `intent-${i}`,
        agent_did: 'did:chitin:test',
        action_type: 'send_message',
        tier: 1,
        decision: 'approved',
        reason: 'test',
      });
    }
    expect(logger.getAnchors()).toHaveLength(0);

    // Log 3rd entry — should trigger anchor
    await logger.log({
      intent_id: 'intent-2',
      agent_did: 'did:chitin:test',
      action_type: 'send_message',
      tier: 1,
      decision: 'approved',
      reason: 'test',
    });

    expect(logger.getAnchors()).toHaveLength(1);
    expect(logger.getAnchors()[0].entryCount).toBe(3);
    expect(logger.getPendingCount()).toBe(0);
  });

  it('forceAnchor commits pending entries', async () => {
    const logger = new AnchoredAuditLogger(defaultConfig);

    await logger.log({
      intent_id: 'intent-001',
      agent_did: 'did:chitin:test',
      action_type: 'send_message',
      tier: 1,
      decision: 'approved',
      reason: 'test',
    });

    const result = await logger.forceAnchor();
    expect(result).not.toBeNull();
    expect(result!.entryCount).toBe(1);
    expect(logger.getAnchors()).toHaveLength(1);
  });

  it('generateInclusionProof works after anchor', async () => {
    const logger = new AnchoredAuditLogger(defaultConfig);

    for (let i = 0; i < 4; i++) {
      await logger.log({
        intent_id: `intent-${i}`,
        agent_did: 'did:chitin:test',
        action_type: 'send_message',
        tier: 1,
        decision: 'approved',
        reason: 'test',
      });
    }

    const result = await logger.forceAnchor();
    const proof = logger.generateInclusionProof(result!.commitmentId, 2);

    expect(proof).not.toBeNull();
    expect(proof!.commitmentId).toBe(result!.commitmentId);
    expect(proof!.index).toBe(2);
    expect(proof!.leaf).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('query delegates to local logger', async () => {
    const logger = new AnchoredAuditLogger(defaultConfig);

    await logger.log({
      intent_id: 'intent-001',
      agent_did: 'did:chitin:agent-a',
      action_type: 'send_message',
      tier: 1,
      decision: 'approved',
      reason: 'test',
    });

    await logger.log({
      intent_id: 'intent-002',
      agent_did: 'did:chitin:agent-b',
      action_type: 'api_call',
      tier: 2,
      decision: 'rejected',
      reason: 'rate limit',
    });

    const all = await logger.query({});
    expect(all).toHaveLength(2);

    const agentA = await logger.query({ agent_did: 'did:chitin:agent-a' });
    expect(agentA).toHaveLength(1);
    expect(agentA[0].agent_did).toBe('did:chitin:agent-a');
  });
});
