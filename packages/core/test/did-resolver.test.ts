import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DidResolver } from '../src/intent/did-resolver.js';
import type { DidResolverConfig } from '../src/intent/did-resolver.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MOCK_CONFIG: DidResolverConfig = {
  rpcUrl: 'https://mock-rpc.example.com',
  registryAddress: '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432',
  chainId: 8453,
};

const MOCK_OWNER = '0x84b11eDc4c2BB4142605B60Ac631118fddc3bc61';

// ---------------------------------------------------------------------------
// Mock RPC helpers
// ---------------------------------------------------------------------------

function mockRpcResponse(result: string) {
  return {
    ok: true,
    json: async () => ({ result }),
  } as unknown as Response;
}

function mockRpcError(message: string, code: number) {
  return {
    ok: true,
    json: async () => ({ error: { message, code } }),
  } as unknown as Response;
}

/**
 * Encode an address as a 32-byte ABI word.
 */
function encodeAddress(address: string): string {
  const cleaned = address.startsWith('0x') ? address.slice(2) : address;
  return '0x' + cleaned.toLowerCase().padStart(64, '0');
}

/**
 * Encode a string as an ABI response (offset + length + data).
 */
function encodeStringResponse(value: string): string {
  const offsetHex = (32).toString(16).padStart(64, '0'); // offset = 0x20
  const hexBytes = Buffer.from(value, 'utf-8').toString('hex');
  const byteLength = hexBytes.length / 2;
  const lengthHex = byteLength.toString(16).padStart(64, '0');
  const paddedData = hexBytes.padEnd(Math.ceil(hexBytes.length / 64) * 64, '0');
  return '0x' + offsetHex + lengthHex + paddedData;
}

// ---------------------------------------------------------------------------
// Tests: Static methods
// ---------------------------------------------------------------------------

describe('DidResolver.fromAgentId', () => {
  it('produces correct DID format', () => {
    const did = DidResolver.fromAgentId(8453, '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432', 42);
    expect(did).toBe('did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42');
  });

  it('produces correct DID for different chain and agent', () => {
    const did = DidResolver.fromAgentId(84532, '0x8004A818BFB912233c491871b3d84c89A494BD9e', 1);
    expect(did).toBe('did:chitin:84532:0x8004A818BFB912233c491871b3d84c89A494BD9e:1');
  });

  it('handles agentId 0', () => {
    const did = DidResolver.fromAgentId(1, '0x' + 'a'.repeat(40), 0);
    expect(did).toBe('did:chitin:1:0x' + 'a'.repeat(40) + ':0');
  });
});

describe('DidResolver.parseDid', () => {
  it('parses valid DID correctly', () => {
    const parsed = DidResolver.parseDid(
      'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42',
    );

    expect(parsed).not.toBeNull();
    expect(parsed!.chainId).toBe(8453);
    expect(parsed!.registryAddress).toBe('0x8004A169FB4a3325136EB29fA0ceB6D2e539a432');
    expect(parsed!.agentId).toBe(42);
  });

  it('returns null for empty string', () => {
    expect(DidResolver.parseDid('')).toBeNull();
  });

  it('returns null for non-chitin DID', () => {
    expect(DidResolver.parseDid('did:key:abc123')).toBeNull();
  });

  it('returns null for DID with wrong number of components', () => {
    expect(DidResolver.parseDid('did:chitin:8453:0x1234')).toBeNull();
  });

  it('returns null for DID with invalid address (too short)', () => {
    expect(DidResolver.parseDid('did:chitin:8453:0xabc:42')).toBeNull();
  });

  it('returns null for DID with negative chain ID', () => {
    // The regex requires digits, so negative is actually not matched
    expect(DidResolver.parseDid('did:chitin:-1:0x' + 'a'.repeat(40) + ':42')).toBeNull();
  });

  it('returns null for non-string input', () => {
    expect(DidResolver.parseDid(null as unknown as string)).toBeNull();
    expect(DidResolver.parseDid(undefined as unknown as string)).toBeNull();
    expect(DidResolver.parseDid(123 as unknown as string)).toBeNull();
  });

  it('roundtrips with fromAgentId', () => {
    const did = DidResolver.fromAgentId(8453, '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432', 99);
    const parsed = DidResolver.parseDid(did);

    expect(parsed).not.toBeNull();
    expect(parsed!.chainId).toBe(8453);
    expect(parsed!.registryAddress).toBe('0x8004A169FB4a3325136EB29fA0ceB6D2e539a432');
    expect(parsed!.agentId).toBe(99);
  });
});

// ---------------------------------------------------------------------------
// Tests: resolve() and verify()
// ---------------------------------------------------------------------------

describe('DidResolver.resolve', () => {
  let resolver: DidResolver;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    resolver = new DidResolver(MOCK_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('resolves a valid DID with mock RPC', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    // Mock ownerOf response
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    // Mock agentURI response
    fetchSpy.mockResolvedValueOnce(
      mockRpcResponse(encodeStringResponse('https://example.com/agent/42')),
    );

    const resolved = await resolver.resolve(did);

    expect(resolved.did).toBe(did);
    expect(resolved.agentId).toBe(42);
    expect(resolved.ownerAddress).toBe(MOCK_OWNER.toLowerCase());
    expect(resolved.agentUri).toBe('https://example.com/agent/42');
    expect(resolved.verified).toBe(true);
  });

  it('returns verified: false for invalid DID format', async () => {
    const resolved = await resolver.resolve('not-a-did');

    expect(resolved.did).toBe('not-a-did');
    expect(resolved.verified).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns verified: false for wrong chain ID', async () => {
    const did = 'did:chitin:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    const resolved = await resolver.resolve(did);

    expect(resolved.verified).toBe(false);
    expect(resolved.agentId).toBe(42);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns verified: false for wrong registry address', async () => {
    const did = 'did:chitin:8453:0x0000000000000000000000000000000000000001:42';

    const resolved = await resolver.resolve(did);

    expect(resolved.verified).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns verified: false when ownerOf reverts (non-existent token)', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:99999';

    fetchSpy.mockResolvedValueOnce(mockRpcError('execution reverted', -32000));

    const resolved = await resolver.resolve(did);

    expect(resolved.verified).toBe(false);
    expect(resolved.agentId).toBe(99999);
  });

  it('still resolves when agentURI call fails', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    // ownerOf succeeds
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    // agentURI fails
    fetchSpy.mockResolvedValueOnce(mockRpcError('execution reverted', -32000));

    const resolved = await resolver.resolve(did);

    expect(resolved.verified).toBe(true);
    expect(resolved.ownerAddress).toBe(MOCK_OWNER.toLowerCase());
    expect(resolved.agentUri).toBeUndefined();
  });
});

describe('DidResolver.verify', () => {
  let resolver: DidResolver;
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    resolver = new DidResolver(MOCK_CONFIG);
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns true for matching owner', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    // ownerOf
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    // agentURI
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringResponse('https://example.com')));

    const verified = await resolver.verify(did, MOCK_OWNER);
    expect(verified).toBe(true);
  });

  it('returns false for mismatched owner', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringResponse('https://example.com')));

    const verified = await resolver.verify(did, '0x0000000000000000000000000000000000000001');
    expect(verified).toBe(false);
  });

  it('returns true without expectedOwner when token exists', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringResponse('https://example.com')));

    const verified = await resolver.verify(did);
    expect(verified).toBe(true);
  });

  it('returns false for invalid DID', async () => {
    const verified = await resolver.verify('garbage');
    expect(verified).toBe(false);
  });

  it('owner comparison is case-insensitive', async () => {
    const did = 'did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42';

    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeAddress(MOCK_OWNER)));
    fetchSpy.mockResolvedValueOnce(mockRpcResponse(encodeStringResponse('https://example.com')));

    const verified = await resolver.verify(did, MOCK_OWNER.toLowerCase());
    expect(verified).toBe(true);
  });
});
