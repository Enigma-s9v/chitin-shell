import { describe, it, expect, beforeEach } from 'vitest';
import { ChitinShell } from '../../core/src/index.js';
import type { PolicyConfig } from '../../core/src/policy/types.js';
import { McpGateway } from '../src/gateway.js';
import { createMcpMiddleware } from '../src/middleware.js';
import type { McpUpstream, McpToolCall, McpToolResult, McpToolDefinition } from '../src/types.js';

// ---------------------------------------------------------------------------
// Mock Upstream
// ---------------------------------------------------------------------------

class MockUpstream implements McpUpstream {
  private tools: McpToolDefinition[];
  callCount = 0;
  lastCall: McpToolCall | null = null;

  constructor(tools?: McpToolDefinition[]) {
    this.tools = tools ?? [
      {
        name: 'get_weather',
        description: 'Get current weather',
        inputSchema: { type: 'object', properties: { city: { type: 'string' } } },
      },
      {
        name: 'send_notification',
        description: 'Send a push notification',
        inputSchema: { type: 'object', properties: { message: { type: 'string' } } },
      },
      {
        name: 'transfer_money',
        description: 'Transfer money between accounts',
        inputSchema: { type: 'object', properties: { amount: { type: 'number' } } },
      },
    ];
  }

  async listTools(): Promise<McpToolDefinition[]> {
    return this.tools;
  }

  async callTool(call: McpToolCall): Promise<McpToolResult> {
    this.callCount++;
    this.lastCall = call;
    return {
      content: [
        { type: 'text', text: `Result for ${call.name}: ${JSON.stringify(call.arguments)}` },
      ],
    };
  }
}

/** Upstream that throws errors */
class ErrorUpstream implements McpUpstream {
  async listTools(): Promise<McpToolDefinition[]> {
    return [];
  }

  async callTool(_call: McpToolCall): Promise<McpToolResult> {
    throw new Error('Upstream connection refused');
  }
}

/** Upstream that leaks secrets in responses */
class LeakyUpstream implements McpUpstream {
  async listTools(): Promise<McpToolDefinition[]> {
    return [
      { name: 'get_config', description: 'Get config', inputSchema: {} },
    ];
  }

  async callTool(_call: McpToolCall): Promise<McpToolResult> {
    return {
      content: [
        {
          type: 'text',
          text: 'Config loaded. API key: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890. DB: postgres://admin:s3cret@db.prod:5432/main',
        },
      ],
    };
  }
}

// ---------------------------------------------------------------------------
// Test Policy
// ---------------------------------------------------------------------------

const testPolicy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only',
      actions: ['think', 'recall', 'summarize', 'read_file'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk',
      actions: ['send_message'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk',
      actions: ['api_call', 'send_email_new'],
      verification: 'local',
      constraints: {
        rate_limit: { max: 3, window: '1h' },
      },
    },
    tier_3: {
      description: 'Critical',
      actions: ['transfer_funds', 'change_permissions'],
      verification: 'human_approval',
    },
  },
  whitelists: { contacts: ['alice@example.com'] },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('McpGateway', () => {
  let shell: ChitinShell;
  let upstream: MockUpstream;
  let gateway: McpGateway;

  beforeEach(async () => {
    shell = await ChitinShell.create({ policy: testPolicy });
    upstream = new MockUpstream();
    gateway = new McpGateway(shell, upstream);
  });

  // -------------------------------------------------------------------------
  // 1. listTools pass-through
  // -------------------------------------------------------------------------

  it('passes through listTools from upstream', async () => {
    const tools = await gateway.listTools();

    expect(tools).toHaveLength(3);
    expect(tools[0].name).toBe('get_weather');
    expect(tools[1].name).toBe('send_notification');
    expect(tools[2].name).toBe('transfer_money');
  });

  // -------------------------------------------------------------------------
  // 2. Approved tool call (default maps to api_call = Tier 2)
  // -------------------------------------------------------------------------

  it('processes approved tool calls through the pipeline', async () => {
    const result = await gateway.callTool({
      name: 'get_weather',
      arguments: { city: 'Tokyo' },
    });

    expect(result.isError).toBeUndefined();
    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('get_weather');
    expect(result.content[0].text).toContain('Tokyo');
    expect(upstream.callCount).toBe(1);
    expect(upstream.lastCall!.name).toBe('get_weather');
  });

  // -------------------------------------------------------------------------
  // 3. Mapped to Tier 0 — auto-approved
  // -------------------------------------------------------------------------

  it('auto-approves tool calls mapped to Tier 0 actions', async () => {
    const gatewayWithMapping = new McpGateway(shell, upstream, {
      toolMapping: { get_weather: 'read_file' },
    });

    const result = await gatewayWithMapping.callTool({
      name: 'get_weather',
      arguments: { city: 'Osaka' },
    });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('Osaka');
    expect(upstream.callCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // 4. Mapped to Tier 1 with whitelisted recipient — approved
  // -------------------------------------------------------------------------

  it('approves Tier 1 mapped calls with whitelisted recipient', async () => {
    const gatewayWithMapping = new McpGateway(shell, upstream, {
      toolMapping: { send_notification: 'send_message' },
    });

    const result = await gatewayWithMapping.callTool({
      name: 'send_notification',
      arguments: { to: 'alice@example.com', message: 'Hello!' },
    });

    expect(result.isError).toBeUndefined();
    expect(upstream.callCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // 5. Tier 3 — rejected (requires human approval)
  // -------------------------------------------------------------------------

  it('blocks tool calls mapped to Tier 3 actions', async () => {
    const gatewayWithMapping = new McpGateway(shell, upstream, {
      toolMapping: { transfer_money: 'transfer_funds' },
    });

    const result = await gatewayWithMapping.callTool({
      name: 'transfer_money',
      arguments: { amount: 10000 },
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Policy rejected');
    expect(result.content[0].text).toContain('human approval');
    expect(upstream.callCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 6. Unknown action → defaults to Tier 3 → rejected
  // -------------------------------------------------------------------------

  it('rejects unknown custom actions that default to Tier 3', async () => {
    const gatewayWithMapping = new McpGateway(shell, upstream, {
      toolMapping: { transfer_money: 'nuke_everything' },
    });

    const result = await gatewayWithMapping.callTool({
      name: 'transfer_money',
      arguments: {},
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Policy rejected');
    // Unknown actions default to tier 3 which requires human approval
    expect(upstream.callCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // 7. Sanitizes text content in results
  // -------------------------------------------------------------------------

  it('sanitizes secrets in upstream responses', async () => {
    const leaky = new LeakyUpstream();
    const gw = new McpGateway(shell, leaky);

    const result = await gw.callTool({
      name: 'get_config',
      arguments: {},
    });

    // The result should come back but with secrets redacted
    // The sanitizer works on the McpToolResult object via sanitizeObject
    expect(result.content).toBeDefined();
    const text = result.content[0].text ?? '';
    expect(text).toContain('[REDACTED:');
    expect(text).not.toContain('sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    expect(text).not.toContain('postgres://admin:s3cret');
  });

  // -------------------------------------------------------------------------
  // 8. Handles upstream errors gracefully
  // -------------------------------------------------------------------------

  it('handles upstream errors gracefully', async () => {
    const errorUpstream = new ErrorUpstream();
    const gw = new McpGateway(shell, errorUpstream);

    const result = await gw.callTool({
      name: 'any_tool',
      arguments: {},
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBeDefined();
    // The error gets caught by the executor and sanitized
  });

  // -------------------------------------------------------------------------
  // 9. blockUnmapped rejects unmapped tools
  // -------------------------------------------------------------------------

  it('blocks unmapped tools when blockUnmapped is true', async () => {
    const gw = new McpGateway(shell, upstream, {
      blockUnmapped: true,
      toolMapping: { get_weather: 'read_file' },
    });

    // Mapped tool should work
    const okResult = await gw.callTool({
      name: 'get_weather',
      arguments: { city: 'Tokyo' },
    });
    expect(okResult.isError).toBeUndefined();

    // Unmapped tool should be blocked
    const blockedResult = await gw.callTool({
      name: 'send_notification',
      arguments: {},
    });
    expect(blockedResult.isError).toBe(true);
    expect(blockedResult.content[0].text).toContain('not mapped');
    expect(blockedResult.content[0].text).toContain('unmapped tools are blocked');
  });

  // -------------------------------------------------------------------------
  // 10. Custom defaultActionType for unmapped tools
  // -------------------------------------------------------------------------

  it('uses custom defaultActionType for unmapped tools', async () => {
    const gw = new McpGateway(shell, upstream, {
      defaultActionType: 'read_file', // Tier 0: auto-approve
    });

    const result = await gw.callTool({
      name: 'get_weather',
      arguments: { city: 'Kyoto' },
    });

    // read_file is Tier 0 = auto-approved
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('Kyoto');
    expect(upstream.callCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // 11. Rate limiting applies across gateway calls
  // -------------------------------------------------------------------------

  it('enforces rate limits across multiple gateway calls', async () => {
    // The test policy has a rate limit of max:3 per 1h for api_call (Tier 2)
    // Default action type is api_call, so unmapped tools hit the rate limit

    const results: McpToolResult[] = [];

    // Make 4 calls — the first 3 should succeed, the 4th should be rate-limited
    for (let i = 0; i < 4; i++) {
      const result = await gateway.callTool({
        name: 'get_weather',
        arguments: { city: `City${i}` },
      });
      results.push(result);
    }

    // First 3 should succeed
    for (let i = 0; i < 3; i++) {
      expect(results[i].isError).toBeUndefined();
    }

    // 4th should be rate-limited
    expect(results[3].isError).toBe(true);
    expect(results[3].content[0].text).toContain('Policy rejected');
    expect(results[3].content[0].text).toContain('Rate limit');
  });

  // -------------------------------------------------------------------------
  // 12. Rejection reasons are meaningful
  // -------------------------------------------------------------------------

  it('includes meaningful rejection reasons in error results', async () => {
    // Non-whitelisted recipient for Tier 1
    const gw = new McpGateway(shell, upstream, {
      toolMapping: { send_notification: 'send_message' },
    });

    const result = await gw.callTool({
      name: 'send_notification',
      arguments: { to: 'evil@hacker.com', message: 'hey' },
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Policy rejected');
    expect(result.content[0].text).toContain('not in the approved contacts whitelist');
  });

  // -------------------------------------------------------------------------
  // 13. Tool mapping works for custom action types
  // -------------------------------------------------------------------------

  it('applies custom tool mapping correctly', async () => {
    const gw = new McpGateway(shell, upstream, {
      toolMapping: {
        get_weather: 'think',           // Tier 0
        send_notification: 'api_call',  // Tier 2
        transfer_money: 'transfer_funds', // Tier 3
      },
    });

    // Tier 0 — auto-approved
    const t0 = await gw.callTool({ name: 'get_weather', arguments: {} });
    expect(t0.isError).toBeUndefined();

    // Tier 2 — approved with verification
    const t2 = await gw.callTool({ name: 'send_notification', arguments: {} });
    expect(t2.isError).toBeUndefined();

    // Tier 3 — rejected
    const t3 = await gw.callTool({ name: 'transfer_money', arguments: {} });
    expect(t3.isError).toBe(true);
    expect(t3.content[0].text).toContain('human approval');
  });
});

// ---------------------------------------------------------------------------
// Middleware Tests
// ---------------------------------------------------------------------------

describe('createMcpMiddleware', () => {
  let shell: ChitinShell;

  beforeEach(async () => {
    shell = await ChitinShell.create({ policy: testPolicy });
  });

  // -------------------------------------------------------------------------
  // 14. Middleware function works as a simple wrapper
  // -------------------------------------------------------------------------

  it('wraps a callTool function with Shell verification', async () => {
    const middleware = createMcpMiddleware({ shell });

    const call: McpToolCall = {
      name: 'get_weather',
      arguments: { city: 'Tokyo' },
    };

    const next = async (c: McpToolCall): Promise<McpToolResult> => ({
      content: [{ type: 'text', text: `Weather in ${c.arguments.city}: sunny` }],
    });

    const result = await middleware(call, next);

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('sunny');
  });

  // -------------------------------------------------------------------------
  // 15. Middleware blocks rejected calls
  // -------------------------------------------------------------------------

  it('blocks rejected calls without calling next', async () => {
    const middleware = createMcpMiddleware({
      shell,
      config: { toolMapping: { dangerous_tool: 'transfer_funds' } },
    });

    let nextCalled = false;
    const next = async (_c: McpToolCall): Promise<McpToolResult> => {
      nextCalled = true;
      return { content: [{ type: 'text', text: 'Should not reach here' }] };
    };

    const result = await middleware(
      { name: 'dangerous_tool', arguments: {} },
      next,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Policy rejected');
    expect(nextCalled).toBe(false);
  });

  // -------------------------------------------------------------------------
  // 16. Middleware blockUnmapped option
  // -------------------------------------------------------------------------

  it('blocks unmapped tools when blockUnmapped is true', async () => {
    const middleware = createMcpMiddleware({
      shell,
      config: { blockUnmapped: true },
    });

    const next = async (_c: McpToolCall): Promise<McpToolResult> => ({
      content: [{ type: 'text', text: 'Should not reach' }],
    });

    const result = await middleware(
      { name: 'unknown_tool', arguments: {} },
      next,
    );

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not mapped');
    expect(result.content[0].text).toContain('unmapped tools are blocked');
  });

  // -------------------------------------------------------------------------
  // 17. Middleware handles next() errors
  // -------------------------------------------------------------------------

  it('handles errors from the next function gracefully', async () => {
    const middleware = createMcpMiddleware({ shell });

    const next = async (_c: McpToolCall): Promise<McpToolResult> => {
      throw new Error('Connection timeout');
    };

    const result = await middleware(
      { name: 'some_tool', arguments: {} },
      next,
    );

    // The error is caught by the executor and returned as an error result
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBeDefined();
  });
});
