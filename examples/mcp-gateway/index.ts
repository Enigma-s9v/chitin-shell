/**
 * Chitin Shell — MCP Gateway Example
 *
 * This demonstrates how to use Chitin Shell as a security gateway
 * between an MCP client and upstream MCP servers.
 *
 * Run with:  npx tsx examples/mcp-gateway/index.ts
 */

import { ChitinShell } from '../../packages/core/src/index.js';
import { McpGateway } from '../../packages/mcp/src/index.js';
import type { PolicyConfig } from '../../packages/core/src/index.js';
import type { McpUpstream, McpToolCall, McpToolResult, McpToolDefinition } from '../../packages/mcp/src/index.js';

// ---------------------------------------------------------------------------
// 1. Policy
// ---------------------------------------------------------------------------

const policy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only',
      actions: ['read_file', 'list_directory', 'think'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk writes',
      actions: ['send_message'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk',
      actions: ['write_file', 'api_call'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical',
      actions: ['execute_command', 'transfer_funds'],
      verification: 'human_approval',
    },
  },
  whitelists: { contacts: ['alice@example.com'] },
};

// ---------------------------------------------------------------------------
// 2. Mock Upstream MCP Server
// ---------------------------------------------------------------------------

class MockFilesystemMcpServer implements McpUpstream {
  async listTools(): Promise<McpToolDefinition[]> {
    return [
      {
        name: 'read_file',
        description: 'Read a file from the filesystem',
        inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
      },
      {
        name: 'write_file',
        description: 'Write content to a file',
        inputSchema: {
          type: 'object',
          properties: {
            path: { type: 'string' },
            content: { type: 'string' },
          },
        },
      },
      {
        name: 'execute_command',
        description: 'Execute a shell command',
        inputSchema: { type: 'object', properties: { command: { type: 'string' } } },
      },
    ];
  }

  async callTool(call: McpToolCall): Promise<McpToolResult> {
    switch (call.name) {
      case 'read_file':
        return {
          content: [{ type: 'text', text: `Contents of ${call.arguments.path}: Hello World!` }],
        };
      case 'write_file':
        return {
          content: [{ type: 'text', text: `Wrote ${(call.arguments.content as string).length} bytes to ${call.arguments.path}` }],
        };
      case 'execute_command':
        return {
          content: [{ type: 'text', text: `Executed: ${call.arguments.command}\nOutput: password=super_secret_123 DB_URL=postgres://admin:pass@db:5432/prod` }],
        };
      default:
        return {
          content: [{ type: 'text', text: `Unknown tool: ${call.name}` }],
          isError: true,
        };
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== Chitin Shell MCP Gateway Example ===\n');

  const shell = await ChitinShell.create({ policy });
  const upstream = new MockFilesystemMcpServer();

  // Create the gateway with tool→action mappings
  const gateway = new McpGateway(shell, upstream, {
    toolMapping: {
      read_file: 'read_file',       // Tier 0
      write_file: 'write_file',     // Tier 2
      execute_command: 'execute_command',  // Tier 3
    },
  });

  // List available tools
  console.log('--- Available Tools ---');
  const tools = await gateway.listTools();
  for (const tool of tools) {
    console.log(`  ${tool.name}: ${tool.description}`);
  }
  console.log();

  // A: read_file — Tier 0, auto-approved
  console.log('--- A: read_file (Tier 0) ---');
  const readResult = await gateway.callTool({ name: 'read_file', arguments: { path: '/tmp/hello.txt' } });
  console.log(`  Error: ${readResult.isError ?? false}`);
  console.log(`  Content: ${readResult.content[0]?.text}`);
  console.log();

  // B: write_file — Tier 2, approved (within rate limit)
  console.log('--- B: write_file (Tier 2) ---');
  const writeResult = await gateway.callTool({
    name: 'write_file',
    arguments: { path: '/tmp/output.txt', content: 'Hello from Chitin Shell!' },
  });
  console.log(`  Error: ${writeResult.isError ?? false}`);
  console.log(`  Content: ${writeResult.content[0]?.text}`);
  console.log();

  // C: execute_command — Tier 3, blocked (requires human approval)
  console.log('--- C: execute_command (Tier 3) ---');
  const execResult = await gateway.callTool({
    name: 'execute_command',
    arguments: { command: 'rm -rf /' },
  });
  console.log(`  Error: ${execResult.isError ?? false}`);
  console.log(`  Content: ${execResult.content[0]?.text}`);
  console.log();
  console.log('  ^ Notice: execute_command was blocked because it requires human approval');

  console.log('\n=== Done ===');
}

main().catch(console.error);
