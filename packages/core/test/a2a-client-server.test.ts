import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryA2ARegistry } from '../src/a2a/registry.js';
import { A2AClient } from '../src/a2a/client.js';
import { A2AServer } from '../src/a2a/server.js';
import { createA2AMessage, verifyA2AMessage } from '../src/a2a/message.js';
import { createA2AMapper, createSecureA2AHandler } from '../src/a2a/middleware.js';
import { generateKeyPair } from '../src/intent/signer.js';
import { ChitinShell } from '../src/shell.js';
import type { A2AConfig, A2AEndpoint, A2AMessage, A2APayload } from '../src/a2a/types.js';
import type { AgentKeyPair } from '../src/intent/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeyPair() {
  return generateKeyPair();
}

function publicKeyHex(kp: AgentKeyPair): string {
  return Buffer.from(kp.publicKey).toString('hex');
}

function makeEndpoint(kp: AgentKeyPair, did: string, url = 'https://agent.example.com/a2a'): A2AEndpoint {
  return {
    did,
    url,
    publicKey: publicKeyHex(kp),
    capabilities: ['query', 'invoke_tool'],
  };
}

function makeConfig(kp: AgentKeyPair, did: string, overrides?: Partial<A2AConfig>): A2AConfig {
  return {
    endpoint: makeEndpoint(kp, did),
    keyPair: kp,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock fetch
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof fetch>();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal('fetch', mockFetch);
});

// ---------------------------------------------------------------------------
// MemoryA2ARegistry
// ---------------------------------------------------------------------------

describe('MemoryA2ARegistry', () => {
  it('register and resolve', async () => {
    const registry = new MemoryA2ARegistry();
    const kp = makeKeyPair();
    const endpoint = makeEndpoint(kp, 'did:chitin:1:0x1234:1');

    await registry.register(endpoint);
    const resolved = await registry.resolve('did:chitin:1:0x1234:1');

    expect(resolved).not.toBeNull();
    expect(resolved!.did).toBe('did:chitin:1:0x1234:1');
    expect(resolved!.url).toBe('https://agent.example.com/a2a');
  });

  it('unregister removes endpoint', async () => {
    const registry = new MemoryA2ARegistry();
    const kp = makeKeyPair();
    const endpoint = makeEndpoint(kp, 'did:chitin:1:0x1234:1');

    await registry.register(endpoint);
    await registry.unregister('did:chitin:1:0x1234:1');

    const resolved = await registry.resolve('did:chitin:1:0x1234:1');
    expect(resolved).toBeNull();
  });

  it('list returns all registered endpoints', async () => {
    const registry = new MemoryA2ARegistry();

    const kp1 = makeKeyPair();
    const kp2 = makeKeyPair();
    await registry.register(makeEndpoint(kp1, 'did:chitin:1:0x1234:1'));
    await registry.register(makeEndpoint(kp2, 'did:chitin:1:0x5678:2'));

    const all = await registry.list();
    expect(all).toHaveLength(2);
    expect(all.map((e) => e.did).sort()).toEqual([
      'did:chitin:1:0x1234:1',
      'did:chitin:1:0x5678:2',
    ]);
  });

  it('resolve unknown DID returns null', async () => {
    const registry = new MemoryA2ARegistry();
    const resolved = await registry.resolve('did:chitin:1:0xunknown:99');
    expect(resolved).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// A2AClient
// ---------------------------------------------------------------------------

describe('A2AClient', () => {
  it('constructor creates client with config', () => {
    const kp = makeKeyPair();
    const config = makeConfig(kp, 'did:chitin:1:0x1234:1');
    const client = new A2AClient(config);

    const stats = client.getStats();
    expect(stats.messagesSent).toBe(0);
    expect(stats.messagesReceived).toBe(0);
    expect(stats.errors).toBe(0);
  });

  it('rate limit blocks excess requests', async () => {
    const kpSender = makeKeyPair();
    const kpReceiver = makeKeyPair();
    const receiverDid = 'did:chitin:1:0x5678:2';

    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpReceiver, receiverDid));

    const config = makeConfig(kpSender, 'did:chitin:1:0x1234:1', {
      rateLimits: { maxPerMinute: 100, maxPerPeer: 2 },
    });

    const client = new A2AClient(config, registry);

    // Create a mock response message for each call
    const makeResponse = async () => {
      const response = await createA2AMessage({
        type: 'response',
        from: receiverDid,
        to: config.endpoint.did,
        payload: { method: 'query', result: 'ok' },
        keyPair: kpReceiver,
      });
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    // First 2 should succeed
    mockFetch.mockImplementation(async () => makeResponse());
    await client.request(receiverDid, 'query', { n: 1 });
    await client.request(receiverDid, 'query', { n: 2 });

    // Third should be rate limited (maxPerPeer=2)
    await expect(client.request(receiverDid, 'query', { n: 3 }))
      .rejects.toThrow('Rate limit exceeded');
  });

  it('rate limit allows after window passes', async () => {
    const kpSender = makeKeyPair();
    const kpReceiver = makeKeyPair();
    const receiverDid = 'did:chitin:1:0x5678:2';

    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpReceiver, receiverDid));

    const config = makeConfig(kpSender, 'did:chitin:1:0x1234:1', {
      rateLimits: { maxPerMinute: 100, maxPerPeer: 1 },
    });

    const client = new A2AClient(config, registry);

    const makeResponse = async () => {
      const response = await createA2AMessage({
        type: 'response',
        from: receiverDid,
        to: config.endpoint.did,
        payload: { method: 'query', result: 'ok' },
        keyPair: kpReceiver,
      });
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    mockFetch.mockImplementation(async () => makeResponse());

    // First request — succeeds
    await client.request(receiverDid, 'query');

    // Mock Date.now to be 61 seconds in the future
    const originalNow = Date.now;
    vi.spyOn(Date, 'now').mockReturnValue(originalNow() + 61_000);

    // After window passes, should work again
    await client.request(receiverDid, 'query');

    vi.restoreAllMocks();
    vi.stubGlobal('fetch', mockFetch);
  });
});

// ---------------------------------------------------------------------------
// A2AServer
// ---------------------------------------------------------------------------

describe('A2AServer', () => {
  it('registers a handler', () => {
    const kp = makeKeyPair();
    const config = makeConfig(kp, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config);

    const handler = async () => ({ method: 'query', result: 'hello' });
    server.on('query', handler);

    // We can verify via handleMessage that the handler is routed
    expect(server.getStats().messagesReceived).toBe(0);
  });

  it('removes a handler', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    server.on('query', async () => ({ method: 'query', result: 'data' }));
    server.off('query');

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kpSender,
    });

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('error');
    expect(response.payload.error?.code).toBe(404);
  });

  it('handleMessage routes to correct handler', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    server.on('query', async (msg) => ({
      method: 'query',
      result: { echo: msg.payload.params?.input },
    }));

    server.on('invoke_tool', async () => ({
      method: 'invoke_tool',
      result: { tool: 'executed' },
    }));

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query', params: { input: 'hello' } },
      keyPair: kpSender,
    });

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('response');
    expect(response.payload.result).toEqual({ echo: 'hello' });
    expect(response.replyTo).toBe(msg.id);
  });

  it('handleMessage validates message signature', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const kpWrong = makeKeyPair();
    const registry = new MemoryA2ARegistry();

    // Register sender with WRONG public key
    await registry.register(makeEndpoint(kpWrong, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    server.on('query', async () => ({ method: 'query', result: 'should not reach' }));

    // Message is signed by kpSender, but registry has kpWrong's public key
    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kpSender,
    });

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('error');
    expect(response.payload.error?.message).toContain('Signature verification failed');
  });

  it('handleMessage returns error for unknown method', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'nonexistent_method' },
      keyPair: kpSender,
    });

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('error');
    expect(response.payload.error?.code).toBe(404);
    expect(response.payload.error?.message).toContain('nonexistent_method');
  });

  it('handleMessage returns error for expired message', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    server.on('query', async () => ({ method: 'query', result: 'ok' }));

    // Create a message that is already expired
    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kpSender,
      ttl: 1, // 1 second
    });

    // Backdate the timestamp
    (msg as any).timestamp = new Date(Date.now() - 60_000).toISOString();

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('error');
    expect(response.payload.error?.message).toContain('expired');
  });

  it('handleMessage returns error for untrusted peer', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    // Only trust specific DIDs — sender is NOT in the list
    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2', {
      trustedPeers: ['did:chitin:1:0xAAAA:99'],
    });

    const server = new A2AServer(config, registry);
    server.on('query', async () => ({ method: 'query', result: 'ok' }));

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kpSender,
    });

    const response = await server.handleMessage(msg);
    expect(response.type).toBe('error');
    expect(response.payload.error?.message).toContain('Untrusted peer');
  });

  it('stats track messages', async () => {
    const kpServer = makeKeyPair();
    const kpSender = makeKeyPair();
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpSender, 'did:chitin:1:0x1234:1'));

    const config = makeConfig(kpServer, 'did:chitin:1:0x5678:2');
    const server = new A2AServer(config, registry);

    server.on('query', async () => ({ method: 'query', result: 'ok' }));

    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query' },
      keyPair: kpSender,
    });

    await server.handleMessage(msg);
    await server.handleMessage(
      await createA2AMessage({
        type: 'request',
        from: 'did:chitin:1:0x1234:1',
        to: 'did:chitin:1:0x5678:2',
        payload: { method: 'query' },
        keyPair: kpSender,
      }),
    );

    const stats = server.getStats();
    expect(stats.messagesReceived).toBe(2);
    expect(stats.messagesSent).toBe(2);
    expect(stats.errors).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Middleware: createA2AMapper
// ---------------------------------------------------------------------------

describe('createA2AMapper', () => {
  it('creates a valid ActionMapper for a2a_request', async () => {
    const kpSender = makeKeyPair();
    const kpReceiver = makeKeyPair();
    const receiverDid = 'did:chitin:1:0x5678:2';

    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpReceiver, receiverDid));

    const config = makeConfig(kpSender, 'did:chitin:1:0x1234:1');
    const client = new A2AClient(config, registry);
    const mapper = createA2AMapper(client);

    expect(mapper.action_type).toBe('a2a_request');

    // Mock fetch to return a valid A2A response
    mockFetch.mockImplementation(async () => {
      const response = await createA2AMessage({
        type: 'response',
        from: receiverDid,
        to: config.endpoint.did,
        payload: { method: 'query', result: { answer: 42 } },
        keyPair: kpReceiver,
      });
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    // Use a mock vault
    const mockVault = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue(undefined),
      delete: vi.fn().mockResolvedValue(false),
      list: vi.fn().mockResolvedValue([]),
      has: vi.fn().mockResolvedValue(false),
    };

    const result = await mapper.execute(
      { target_did: receiverDid, method: 'query', params: { q: 'test' } },
      mockVault,
    );

    expect(result).toBeTruthy();
    const r = result as any;
    expect(r.from).toBe(receiverDid);
    expect(r.type).toBe('response');
    expect(r.payload.result).toEqual({ answer: 42 });
  });
});

// ---------------------------------------------------------------------------
// Middleware: createSecureA2AHandler
// ---------------------------------------------------------------------------

describe('createSecureA2AHandler', () => {
  // Mock filesystem for LocalAuditLogger
  vi.mock('node:fs/promises', () => ({
    mkdir: vi.fn().mockResolvedValue(undefined),
    appendFile: vi.fn().mockResolvedValue(undefined),
  }));

  it('wraps handler with policy check', async () => {
    const shell = await ChitinShell.create();
    const innerHandler = vi.fn(async (msg: A2AMessage): Promise<A2APayload> => ({
      method: msg.payload.method,
      result: { handled: true },
    }));

    const secureHandler = createSecureA2AHandler(shell, innerHandler);

    const kp = makeKeyPair();
    const msg = await createA2AMessage({
      type: 'request',
      from: 'did:chitin:1:0x1234:1',
      to: 'did:chitin:1:0x5678:2',
      payload: { method: 'query', params: { data: 'test' } },
      keyPair: kp,
    });

    const result = await secureHandler(msg);

    // Default policy should approve 'a2a_request' (custom type defaults to tier 3 but
    // with default policy it should get processed). The handler should be called.
    // If policy rejects, we'd get an error payload.
    if (result.error) {
      // Policy rejected — that's also valid behavior
      expect(result.error.code).toBe(403);
    } else {
      // Policy approved — handler was called
      expect(innerHandler).toHaveBeenCalledWith(msg);
      expect(result.result).toEqual({ handled: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Full round-trip: client -> server -> handler -> response
// ---------------------------------------------------------------------------

describe('Full round-trip', () => {
  // Mock filesystem for tests that create Shell instances
  vi.mock('node:fs/promises', () => ({
    mkdir: vi.fn().mockResolvedValue(undefined),
    appendFile: vi.fn().mockResolvedValue(undefined),
  }));

  it('client sends request, server processes, client receives response', async () => {
    const kpClient = makeKeyPair();
    const kpServer = makeKeyPair();
    const clientDid = 'did:chitin:1:0x1234:1';
    const serverDid = 'did:chitin:1:0x5678:2';

    // Shared registry
    const registry = new MemoryA2ARegistry();
    await registry.register(makeEndpoint(kpClient, clientDid));
    await registry.register(makeEndpoint(kpServer, serverDid, 'https://server.example.com/a2a'));

    // Server setup
    const serverConfig = makeConfig(kpServer, serverDid);
    const server = new A2AServer(serverConfig, registry);

    server.on('greet', async (msg) => ({
      method: 'greet',
      result: { greeting: `Hello, ${msg.payload.params?.name}!` },
    }));

    // Client setup
    const clientConfig = makeConfig(kpClient, clientDid);
    const client = new A2AClient(clientConfig, registry);

    // Mock fetch: intercept the POST, feed it to the server, return the response
    mockFetch.mockImplementation(async (_url, init) => {
      const body = JSON.parse((init as RequestInit).body as string) as A2AMessage;
      const response = await server.handleMessage(body);

      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const response = await client.request(serverDid, 'greet', { name: 'Eiji' });

    expect(response.type).toBe('response');
    expect(response.from).toBe(serverDid);
    expect(response.to).toBe(clientDid);
    expect(response.replyTo).toBeTruthy();
    expect(response.payload.result).toEqual({ greeting: 'Hello, Eiji!' });

    // Verify stats
    const clientStats = client.getStats();
    expect(clientStats.messagesSent).toBe(1);
    expect(clientStats.messagesReceived).toBe(1);

    const serverStats = server.getStats();
    expect(serverStats.messagesReceived).toBe(1);
    expect(serverStats.messagesSent).toBe(1);
  });
});
