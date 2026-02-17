/**
 * LangChain Adapter — Type Definitions
 *
 * Defines the configuration types for mapping LangChain tool calls
 * to Chitin Shell Intents. All interfaces are locally defined to
 * avoid a hard dependency on @langchain/core at build time.
 */

import type { ChitinShell } from '@chitin-id/shell-core';
import type { ActionType, SecurityTier } from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// LangChain-compatible interfaces (to avoid hard dependency)
// ---------------------------------------------------------------------------

/** Represents a tool call from LangChain */
export interface LangChainToolCall {
  name: string;
  args: Record<string, unknown>;
  id?: string;
}

/** LangChain-compatible callback handler interface */
export interface LangChainCallbackHandler {
  name: string;
  handleToolStart?(
    tool: { name: string },
    input: string,
    runId: string,
  ): Promise<void>;
  handleToolEnd?(output: string, runId: string): Promise<void>;
  handleToolError?(error: Error, runId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Tool Definition (framework-agnostic)
// ---------------------------------------------------------------------------

/** A framework-agnostic tool definition that can wrap any LangChain tool */
export interface ToolDefinition {
  name: string;
  description: string;
  execute: (input: Record<string, unknown>) => Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Chitin Adapter Configuration
// ---------------------------------------------------------------------------

/** Maps a LangChain tool name to a Chitin action type and security tier */
export interface ChitinToolConfig {
  /** The Chitin action type to map this tool call to */
  actionType: ActionType;
  /** Override the default tier for this action (optional; determined by policy if omitted) */
  tier?: SecurityTier;
  /** Transform the tool input before creating the Intent (optional) */
  mapParams?: (input: Record<string, unknown>) => Record<string, unknown>;
}

/** Configuration for the LangChain adapter */
export interface ChitinLangChainOptions {
  /** The ChitinShell instance to use for Intent-Verify-Execute */
  shell: ChitinShell;
  /** Optional mapping of LangChain tool names to Chitin action configs */
  toolMappings?: Record<string, ChitinToolConfig>;
  /** Default action type for unmapped tools (defaults to the tool name itself) */
  defaultActionType?: ActionType;
}

/** Options for wrapping a single tool with Chitin Shell */
export interface SecureToolOptions {
  /** The ChitinShell instance to use */
  shell: ChitinShell;
  /** Override the action type (defaults to tool.name) */
  actionType?: ActionType;
  /** Transform tool input before creating the Intent */
  mapParams?: (input: Record<string, unknown>) => Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Interception tracking
// ---------------------------------------------------------------------------

/** Represents an intercepted tool call before/after Shell processing */
export interface ToolCallInterception {
  /** The original tool name */
  toolName: string;
  /** The original tool input */
  originalInput: Record<string, unknown>;
  /** The mapped action type sent to Chitin Shell */
  mappedActionType: ActionType;
  /** The mapped params sent to Chitin Shell */
  mappedParams: Record<string, unknown>;
  /** Whether the intent was approved */
  approved: boolean;
  /** The security tier that was applied */
  tier: SecurityTier;
  /** Reason for approval/rejection */
  reason: string;
  /** Timestamp of interception */
  timestamp: string;
}
