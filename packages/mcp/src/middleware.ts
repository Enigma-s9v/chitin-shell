/**
 * MCP Middleware — A simpler functional API for wrapping MCP tool calls
 * with Chitin Shell verification.
 *
 * Use this when you don't have a full McpUpstream interface, just a callTool function.
 */

import type { ChitinShell, ActionMapper, IVault } from '@chitin-id/shell-core';
import type { McpGatewayConfig, McpToolCall, McpToolResult } from './types.js';

export interface McpMiddlewareOptions {
  shell: ChitinShell;
  config?: McpGatewayConfig;
}

/**
 * Wraps an upstream callTool function with Chitin Shell verification.
 *
 * Returns a function that takes a tool call and a `next` callback (the actual upstream),
 * runs the call through the Shell pipeline, and returns the result.
 *
 * @example
 * ```ts
 * const middleware = createMcpMiddleware({ shell });
 * const result = await middleware(call, (c) => upstreamServer.callTool(c));
 * ```
 */
export function createMcpMiddleware(
  options: McpMiddlewareOptions,
): (call: McpToolCall, next: (call: McpToolCall) => Promise<McpToolResult>) => Promise<McpToolResult> {
  const { shell, config } = options;
  const resolvedConfig: Required<McpGatewayConfig> = {
    toolMapping: config?.toolMapping ?? {},
    defaultActionType: config?.defaultActionType ?? 'api_call',
    blockUnmapped: config?.blockUnmapped ?? false,
  };

  return async (call: McpToolCall, next: (call: McpToolCall) => Promise<McpToolResult>): Promise<McpToolResult> => {
    const actionType = resolveActionType(call.name, resolvedConfig);

    // Block unmapped tools if configured
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

    // Create Intent
    const intent = shell.createIntent({
      action: actionType,
      params: {
        _mcp_tool: call.name,
        ...call.arguments,
      },
    });

    // Register a temporary mapper that delegates to the next function
    const tempMapper: ActionMapper = {
      action_type: actionType,
      async execute(_params: Record<string, unknown>, _vault: IVault): Promise<unknown> {
        return next(call);
      },
    };

    shell.registerMapper(tempMapper);

    try {
      const result = await shell.execute(intent);

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
        content: [{ type: 'text', text: `Middleware error: ${message}` }],
        isError: true,
      };
    }
  };
}

function resolveActionType(toolName: string, config: Required<McpGatewayConfig>): string | null {
  const mapped = config.toolMapping[toolName];
  if (mapped) return mapped;
  if (config.blockUnmapped) return null;
  return config.defaultActionType;
}
