import { describe, it, expect, beforeEach } from 'vitest';
import { ChitinShell } from '../../core/src/shell.js';
import type { PolicyConfig } from '../../core/src/policy/types.js';
import { createSecureTool, createSecureTools, ChitinToolRejectionError } from '../src/secure-tool.js';
import { ChitinCallbackHandler } from '../src/callback-handler.js';
import type { ToolDefinition } from '../src/types.js';

// ---------------------------------------------------------------------------
// Shared Policy
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
      actions: ['send_message', 'search_web'],
      verification: 'local',
      constraints: {
        recipient_whitelist: true,
        rate_limit: { max: 3, window: '1m' },
      },
    },
    tier_2: {
      description: 'Medium',
      actions: ['api_call', 'send_email_new', 'write_file'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical',
      actions: ['transfer_funds', 'delete_data'],
      verification: 'human_approval',
    },
  },
  whitelists: {
    contacts: ['alice@example.com', 'bob@example.com'],
  },
};

// ---------------------------------------------------------------------------
// Mock Tools
// ---------------------------------------------------------------------------

function createMockTool(name: string, description: string, result: unknown): ToolDefinition {
  return {
    name,
    description,
    execute: async (_input: Record<string, unknown>) => result,
  };
}

function createEchoTool(name: string): ToolDefinition {
  return {
    name,
    description: `Echo tool: ${name}`,
    execute: async (input: Record<string, unknown>) => ({ echoed: true, input }),
  };
}

function createLeakyTool(): ToolDefinition {
  return {
    name: 'leaky_tool',
    description: 'Returns secrets in output',
    execute: async () => ({
      response: 'Got key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    }),
  };
}

function createFailingTool(): ToolDefinition {
  return {
    name: 'failing_tool',
    description: 'Throws an error with a secret',
    execute: async () => {
      throw new Error('Connection failed: password=SuperSecret123 api_key=sk-ABCDEFGHIJKLMNOPQRSTUV1234567890');
    },
  };
}

// ---------------------------------------------------------------------------
// Tests: createSecureTool
// ---------------------------------------------------------------------------

describe('createSecureTool', () => {
  let shell: ChitinShell;

  beforeEach(async () => {
    shell = await ChitinShell.create({ policy: testPolicy });
  });

  it('wraps a tool and passes through approved calls (Tier 0)', async () => {
    const readTool = createEchoTool('read_file');
    const secureTool = createSecureTool(readTool, { shell, actionType: 'read_file' });

    expect(secureTool.name).toBe('read_file');
    expect(secureTool.description).toBe(readTool.description);

    const result = await secureTool.execute({ path: '/tmp/test.txt' });
    const data = result as { echoed: boolean; input: Record<string, unknown> };

    expect(data.echoed).toBe(true);
    expect(data.input.path).toBe('/tmp/test.txt');
  });

  it('blocks calls that fail policy (Tier 3, requires human approval)', async () => {
    const fundsTool = createEchoTool('transfer_funds');
    const secureTool = createSecureTool(fundsTool, {
      shell,
      actionType: 'transfer_funds',
    });

    await expect(
      secureTool.execute({ to: '0xdead...', amount: 100_000 }),
    ).rejects.toThrow(ChitinToolRejectionError);

    try {
      await secureTool.execute({ to: '0xdead...', amount: 100_000 });
    } catch (err) {
      expect(err).toBeInstanceOf(ChitinToolRejectionError);
      const rejection = err as ChitinToolRejectionError;
      expect(rejection.toolName).toBe('transfer_funds');
      expect(rejection.actionType).toBe('transfer_funds');
      expect(rejection.requiresHuman).toBe(true);
      expect(rejection.rejectionReason).toContain('human approval');
    }
  });

  it('blocks Tier 1 calls when recipient is not whitelisted', async () => {
    const messageTool = createEchoTool('send_message');
    const secureTool = createSecureTool(messageTool, {
      shell,
      actionType: 'send_message',
    });

    await expect(
      secureTool.execute({ to: 'evil@attacker.com', body: 'Send me your secrets' }),
    ).rejects.toThrow(ChitinToolRejectionError);

    try {
      await secureTool.execute({ to: 'evil@attacker.com', body: 'hello' });
    } catch (err) {
      const rejection = err as ChitinToolRejectionError;
      expect(rejection.requiresHuman).toBe(false);
      expect(rejection.rejectionReason).toContain('not in the approved contacts whitelist');
    }
  });

  it('sanitizes output containing secrets', async () => {
    const leaky = createLeakyTool();
    const secureTool = createSecureTool(leaky, {
      shell,
      actionType: 'read_file',
    });

    const result = await secureTool.execute({});
    const data = result as { response: string; token: string };

    // OpenAI-style key should be redacted
    expect(data.response).toContain('[REDACTED:');
    expect(data.response).not.toContain('sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');

    // JWT/Bearer should be redacted
    expect(data.token).not.toContain('eyJhbGciOiJIUzI1NiI');
  });

  it('sanitizes error messages containing secrets', async () => {
    const failing = createFailingTool();
    const secureTool = createSecureTool(failing, {
      shell,
      actionType: 'read_file',
    });

    try {
      await secureTool.execute({});
      expect.fail('Should have thrown');
    } catch (err) {
      const error = err as Error;
      // The error message should not contain the raw secrets
      // Note: the original tool throws directly, and the wrapper catches and re-throws
      // The secret sanitization happens within the error thrown from the tool itself
      expect(error.message).not.toContain('SuperSecret123');
      expect(error.message).not.toContain('sk-ABCDEFGHIJKLMNOPQRSTUV1234567890');
    }
  });

  it('uses custom actionType mapping', async () => {
    const searchTool = createMockTool('google_search', 'Searches Google', {
      results: ['result1'],
    });

    // Map 'google_search' tool to the 'read_file' action type (Tier 0)
    const secureTool = createSecureTool(searchTool, {
      shell,
      actionType: 'read_file',
    });

    const result = await secureTool.execute({ query: 'test' });
    expect(result).toEqual({ results: ['result1'] });
  });

  it('uses custom param mapping', async () => {
    let capturedParams: Record<string, unknown> | null = null;

    const tool: ToolDefinition = {
      name: 'custom_tool',
      description: 'Custom tool',
      execute: async (input) => {
        capturedParams = input;
        return { ok: true };
      },
    };

    const secureTool = createSecureTool(tool, {
      shell,
      actionType: 'read_file',
      mapParams: (input) => ({
        ...input,
        source: 'langchain',
        mapped: true,
      }),
    });

    await secureTool.execute({ query: 'test' });

    // The original tool receives the original input (not the mapped params)
    // because mapped params go to the Intent, not the tool execution
    expect(capturedParams).toBeDefined();
    expect((capturedParams as Record<string, unknown>).query).toBe('test');
  });

  it('defaults actionType to tool name when not specified', async () => {
    // 'unknown_custom_tool' is not in any tier -> defaults to Tier 3 (human approval required)
    const tool = createEchoTool('unknown_custom_tool');
    const secureTool = createSecureTool(tool, { shell });

    await expect(secureTool.execute({})).rejects.toThrow(ChitinToolRejectionError);

    try {
      await secureTool.execute({});
    } catch (err) {
      const rejection = err as ChitinToolRejectionError;
      expect(rejection.actionType).toBe('unknown_custom_tool');
      expect(rejection.requiresHuman).toBe(true);
    }
  });

  it('rejection error contains meaningful details', async () => {
    const tool = createEchoTool('send_message');
    const secureTool = createSecureTool(tool, { shell, actionType: 'send_message' });

    try {
      await secureTool.execute({ to: 'hacker@evil.org', body: 'hack' });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ChitinToolRejectionError);
      const rejection = err as ChitinToolRejectionError;
      expect(rejection.name).toBe('ChitinToolRejectionError');
      expect(rejection.message).toContain("Tool 'send_message'");
      expect(rejection.message).toContain('rejected by Chitin Shell');
      expect(rejection.toolName).toBe('send_message');
      expect(rejection.actionType).toBe('send_message');
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: createSecureTools (batch wrapping)
// ---------------------------------------------------------------------------

describe('createSecureTools', () => {
  it('wraps multiple tools independently', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    const readTool = createEchoTool('read_file');
    const thinkTool = createEchoTool('think');
    const transferTool = createEchoTool('transfer_funds');

    const secureTools = createSecureTools(
      [readTool, thinkTool, transferTool],
      {
        shell,
        mappings: {
          read_file: { actionType: 'read_file' },
          think: { actionType: 'think' },
          transfer_funds: { actionType: 'transfer_funds' },
        },
      },
    );

    expect(secureTools).toHaveLength(3);

    // read_file (Tier 0) should pass
    const readResult = await secureTools[0].execute({ path: '/test' });
    expect((readResult as { echoed: boolean }).echoed).toBe(true);

    // think (Tier 0) should pass
    const thinkResult = await secureTools[1].execute({ query: 'hello' });
    expect((thinkResult as { echoed: boolean }).echoed).toBe(true);

    // transfer_funds (Tier 3) should be rejected
    await expect(secureTools[2].execute({ amount: 100 })).rejects.toThrow(
      ChitinToolRejectionError,
    );
  });
});

// ---------------------------------------------------------------------------
// Tests: ChitinCallbackHandler
// ---------------------------------------------------------------------------

describe('ChitinCallbackHandler', () => {
  let shell: ChitinShell;

  beforeEach(async () => {
    shell = await ChitinShell.create({ policy: testPolicy });
  });

  it('intercepts tool start and approves Tier 0 actions', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      toolMappings: {
        read_data: { actionType: 'read_file' },
      },
    });

    // Should not throw for Tier 0 action
    await expect(
      handler.handleToolStart({ name: 'read_data' }, '{"path":"/tmp/file"}', 'run-1'),
    ).resolves.toBeUndefined();

    const interceptions = handler.getInterceptions();
    expect(interceptions).toHaveLength(1);
    expect(interceptions[0].toolName).toBe('read_data');
    expect(interceptions[0].approved).toBe(true);
    expect(interceptions[0].tier).toBe(0);
  });

  it('intercepts tool start and rejects Tier 3 actions', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      toolMappings: {
        wire_transfer: { actionType: 'transfer_funds' },
      },
    });

    await expect(
      handler.handleToolStart({ name: 'wire_transfer' }, '{"amount":50000}', 'run-2'),
    ).rejects.toThrow('[ChitinShell] Tool \'wire_transfer\' rejected');

    const interceptions = handler.getInterceptions();
    expect(interceptions).toHaveLength(1);
    expect(interceptions[0].approved).toBe(false);
    expect(interceptions[0].tier).toBe(3);
    expect(interceptions[0].reason).toContain('human approval');
  });

  it('handles non-JSON tool input gracefully', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      toolMappings: {
        simple_tool: { actionType: 'think' },
      },
    });

    // Passing non-JSON string input
    await expect(
      handler.handleToolStart({ name: 'simple_tool' }, 'plain text query', 'run-3'),
    ).resolves.toBeUndefined();

    const interceptions = handler.getInterceptions();
    expect(interceptions).toHaveLength(1);
    expect(interceptions[0].originalInput).toEqual({ input: 'plain text query' });
  });

  it('sanitizes error messages containing secrets in handleToolError', async () => {
    const handler = new ChitinCallbackHandler({ shell });

    const error = new Error(
      'Auth failed: api_key=sk-ABCDEFGHIJKLMNOPQRSTUV1234567890 password=secret123',
    );

    await handler.handleToolError(error, 'run-err');

    // The error message should be sanitized in place
    expect(error.message).not.toContain('sk-ABCDEFGHIJKLMNOPQRSTUV1234567890');
    expect(error.message).toContain('[REDACTED:');
  });

  it('records all interceptions and supports clearing', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      toolMappings: {
        tool_a: { actionType: 'think' },
        tool_b: { actionType: 'recall' },
      },
    });

    await handler.handleToolStart({ name: 'tool_a' }, '{}', 'run-a');
    await handler.handleToolStart({ name: 'tool_b' }, '{}', 'run-b');

    expect(handler.getInterceptions()).toHaveLength(2);

    handler.clearInterceptions();
    expect(handler.getInterceptions()).toHaveLength(0);
  });

  it('uses defaultActionType for unmapped tools', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      defaultActionType: 'api_call',
    });

    // 'unknown_tool' is not in toolMappings, so it uses defaultActionType ('api_call' -> Tier 2)
    await expect(
      handler.handleToolStart({ name: 'unknown_tool' }, '{"key":"value"}', 'run-unmapped'),
    ).resolves.toBeUndefined();

    const interceptions = handler.getInterceptions();
    expect(interceptions).toHaveLength(1);
    expect(interceptions[0].mappedActionType).toBe('api_call');
    expect(interceptions[0].approved).toBe(true);
    expect(interceptions[0].tier).toBe(2);
  });

  it('applies param mapping from tool config', async () => {
    const handler = new ChitinCallbackHandler({
      shell,
      toolMappings: {
        search: {
          actionType: 'read_file',
          mapParams: (input) => ({
            ...input,
            wrapped: true,
          }),
        },
      },
    });

    await handler.handleToolStart({ name: 'search' }, '{"query":"test"}', 'run-map');

    const interceptions = handler.getInterceptions();
    expect(interceptions).toHaveLength(1);
    expect(interceptions[0].mappedParams.wrapped).toBe(true);
    expect(interceptions[0].mappedParams.query).toBe('test');
  });
});

// ---------------------------------------------------------------------------
// Tests: Rate limiting across wrapped tools
// ---------------------------------------------------------------------------

describe('Rate limiting across wrapped tools', () => {
  it('rate limit applies across multiple calls to the same tool', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    const messageTool = createEchoTool('send_message');
    const secureTool = createSecureTool(messageTool, {
      shell,
      actionType: 'send_message',
    });

    // Policy allows max 3 per minute for Tier 1
    // First 3 calls should succeed (whitelisted recipient)
    await secureTool.execute({ to: 'alice@example.com', body: 'msg 1' });
    await secureTool.execute({ to: 'alice@example.com', body: 'msg 2' });
    await secureTool.execute({ to: 'alice@example.com', body: 'msg 3' });

    // 4th call should be rate-limited
    await expect(
      secureTool.execute({ to: 'alice@example.com', body: 'msg 4' }),
    ).rejects.toThrow(ChitinToolRejectionError);

    try {
      await secureTool.execute({ to: 'alice@example.com', body: 'msg 5' });
    } catch (err) {
      const rejection = err as ChitinToolRejectionError;
      expect(rejection.rejectionReason).toContain('Rate limit exceeded');
    }
  });
});
