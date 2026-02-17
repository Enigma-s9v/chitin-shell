/**
 * MCP Gateway — Type Definitions
 *
 * MCP-compatible types defined locally so we don't depend on @modelcontextprotocol/sdk.
 * These are structurally compatible with the official SDK types.
 */

/** MCP tool definition — describes a tool available from an upstream server */
export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

/** MCP tool call request — what the client sends when invoking a tool */
export interface McpToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

/** MCP tool call result — what we return to the client */
export interface McpToolResult {
  content: McpContentBlock[];
  isError?: boolean;
}

/** A single content block in an MCP result */
export interface McpContentBlock {
  type: 'text' | 'image' | 'resource';
  text?: string;
  data?: string;
  mimeType?: string;
}

/** Gateway configuration — controls how MCP tool names map to Chitin action types */
export interface McpGatewayConfig {
  /** Tool name -> Chitin action type mapping. If not specified, tool name is used as action type */
  toolMapping?: Record<string, string>;
  /** Default action type for unmapped tools (default: 'api_call') */
  defaultActionType?: string;
  /** Whether to block unmapped tools entirely (default: false) */
  blockUnmapped?: boolean;
}

/** Upstream MCP server interface — implement this to connect to actual MCP servers */
export interface McpUpstream {
  listTools(): Promise<McpToolDefinition[]>;
  callTool(call: McpToolCall): Promise<McpToolResult>;
}
