/**
 * MCP Gateway — Routes MCP tool calls through Chitin Shell's Intent-Verify-Execute pipeline.
 *
 * Sits between an MCP client (Claude, etc.) and upstream MCP servers, ensuring every
 * tool call is policy-checked, credential-injected, and output-sanitized.
 */

import type { ChitinShell, ActionMapper, IVault } from '@chitin-id/shell-core';
import type {
  McpGatewayConfig,
  McpUpstream,
  McpToolDefinition,
  McpToolCall,
  McpToolResult,
} from './types.js';

export class McpGateway {
  private shell: ChitinShell;
  private upstream: McpUpstream;
  private config: Required<McpGatewayConfig>;

  constructor(shell: ChitinShell, upstream: McpUpstream, config?: McpGatewayConfig) {
    this.shell = shell;
    this.upstream = upstream;
    this.config = {
      toolMapping: config?.toolMapping ?? {},
      defaultActionType: config?.defaultActionType ?? 'api_call',
      blockUnmapped: config?.blockUnmapped ?? false,
    };
  }

  /** List available tools from upstream (pass-through) */
  async listTools(): Promise<McpToolDefinition[]> {
    return this.upstream.listTools();
  }

  /** Process a tool call through Shell pipeline */
  async callTool(call: McpToolCall): Promise<McpToolResult> {
    const actionType = this.resolveActionType(call.name);

    // Block unmapped tools if configured to do so
    if (actionType === null) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool '${call.name}' is not mapped to any Chitin action and unmapped tools are blocked`,
          },
        ],
        isError: true,
      };
    }

    // Create an Intent for this tool call
    const intent = this.shell.createIntent({
      action: actionType,
      params: {
        _mcp_tool: call.name,
        ...call.arguments,
      },
    });

    // Register a temporary mapper that forwards to the upstream MCP server
    const upstream = this.upstream;
    const originalCall = call;

    const tempMapper: ActionMapper = {
      action_type: actionType,
      async execute(_params: Record<string, unknown>, _vault: IVault): Promise<unknown> {
        return upstream.callTool(originalCall);
      },
    };

    this.shell.registerMapper(tempMapper);

    try {
      const result = await this.shell.execute(intent);

      // Policy rejected the tool call
      if (!result.verification.approved) {
        return {
          content: [
            {
              type: 'text',
              text: `Policy rejected: ${result.verification.reason}`,
            },
          ],
          isError: true,
        };
      }

      // Execution failed (no mapper, upstream error, etc.)
      if (!result.execution || result.execution.status === 'error') {
        return {
          content: [
            {
              type: 'text',
              text: result.execution?.error ?? 'Execution failed with unknown error',
            },
          ],
          isError: true,
        };
      }

      // Success — the execution data is the McpToolResult from upstream (sanitized by shell)
      const upstreamResult = result.execution.data as McpToolResult | undefined;
      if (!upstreamResult || !upstreamResult.content) {
        return {
          content: [{ type: 'text', text: 'Empty response from upstream' }],
          isError: false,
        };
      }

      return upstreamResult;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: 'text', text: `Gateway error: ${message}` }],
        isError: true,
      };
    }
  }

  /**
   * Resolve the Chitin action type for a given MCP tool name.
   * Returns null if the tool is unmapped and blockUnmapped is true.
   */
  private resolveActionType(toolName: string): string | null {
    // Check explicit mapping first
    const mapped = this.config.toolMapping[toolName];
    if (mapped) return mapped;

    // If blocking unmapped tools and this tool has no explicit mapping
    if (this.config.blockUnmapped) return null;

    // Fall through to default action type
    return this.config.defaultActionType;
  }
}
