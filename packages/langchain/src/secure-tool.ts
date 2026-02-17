/**
 * Secure Tool Wrapper
 *
 * Wraps a LangChain-compatible tool definition with Chitin Shell's
 * Intent-Verify-Execute pipeline. The original tool only executes
 * if the Shell approves the intent.
 */

import type { ChitinShell } from '@chitin-id/shell-core';
import type { ToolDefinition, SecureToolOptions } from './types.js';

/**
 * Wraps a tool with Chitin Shell verification.
 *
 * The returned tool:
 * 1. Creates an Intent from the tool input
 * 2. Runs through the Shell's policy engine
 * 3. If rejected, throws an error with the rejection reason
 * 4. If approved, calls the original tool
 * 5. Sanitizes the output before returning
 *
 * @param tool - The original tool definition to wrap
 * @param options - Configuration for the Shell integration
 * @returns A new tool definition that enforces Shell verification
 */
export function createSecureTool(
  tool: ToolDefinition,
  options: SecureToolOptions,
): ToolDefinition {
  const { shell, actionType, mapParams } = options;
  const resolvedActionType = actionType ?? tool.name;

  return {
    name: tool.name,
    description: tool.description,
    execute: async (input: Record<string, unknown>): Promise<unknown> => {
      // Step 1: Map params if a mapper is provided
      const mappedParams = mapParams ? mapParams(input) : input;

      // Step 2: Create an Intent
      const intent = shell.createIntent({
        action: resolvedActionType,
        params: mappedParams,
        context: { triggered_by: 'agent_internal' },
      });

      // Step 3: Run through Intent-Verify-Execute
      const result = await shell.execute(intent);

      // Step 4: If rejected, throw with the reason
      if (!result.verification.approved) {
        const error = new ChitinToolRejectionError(
          tool.name,
          resolvedActionType,
          result.verification.reason,
          result.verification.requires_human ?? false,
        );
        throw error;
      }

      // Step 5: If the Shell executed via a registered mapper, return that result
      if (result.execution) {
        if (result.execution.status === 'error') {
          // Mapper-level error (e.g., no mapper registered) — fall through to original tool
          if (result.execution.error?.includes('No mapper registered')) {
            // No mapper registered — execute the original tool directly
            return await executeOriginalTool(tool, input, shell);
          }
          throw new Error(`Chitin Shell execution error: ${result.execution.error}`);
        }
        return result.execution.data;
      }

      // Approved but no execution (shouldn't happen in normal flow, but handle gracefully)
      return await executeOriginalTool(tool, input, shell);
    },
  };
}

/**
 * Wraps multiple tools at once with the same Shell instance.
 *
 * @param tools - Array of tool definitions to wrap
 * @param options - Shared configuration (shell instance, optional per-tool mappings)
 * @returns Array of wrapped tool definitions
 */
export function createSecureTools(
  tools: ToolDefinition[],
  options: { shell: ChitinShell; mappings?: Record<string, Omit<SecureToolOptions, 'shell'>> },
): ToolDefinition[] {
  return tools.map(tool => {
    const toolOptions: SecureToolOptions = {
      shell: options.shell,
      ...options.mappings?.[tool.name],
    };
    return createSecureTool(tool, toolOptions);
  });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Executes the original tool and sanitizes its output through the Shell.
 * This is used when the Shell approves but has no mapper registered.
 */
async function executeOriginalTool(
  tool: ToolDefinition,
  input: Record<string, unknown>,
  _shell: ChitinShell,
): Promise<unknown> {
  let raw: unknown;

  try {
    raw = await tool.execute(input);
  } catch (err) {
    // Sanitize error messages to prevent secret leakage through errors
    const message = err instanceof Error ? err.message : String(err);
    const sanitized = sanitizeString(message);
    throw new Error(sanitized);
  }

  // Sanitize output to prevent secret leakage
  const serialized = typeof raw === 'string' ? raw : JSON.stringify(raw);

  if (containsSecretPatterns(serialized)) {
    return sanitizeOutput(raw);
  }

  return raw;
}

/** Quick check for common secret patterns in output */
function containsSecretPatterns(text: string): boolean {
  const patterns = [
    /sk-ant-[a-zA-Z0-9_-]{20,}/,
    /sk-[a-zA-Z0-9_-]{20,}/,
    /AIza[a-zA-Z0-9_-]{35}/,
    /AKIA[A-Z0-9]{16}/,
    /gh[pos]_[a-zA-Z0-9]{20,}/,
    /xox[bpras]-[a-zA-Z0-9-]+/,
    /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
    /(?:password|secret|api[_-]?key)\s*[=:]\s*['"]?[^\s'"]+/i,
  ];

  return patterns.some(p => p.test(text));
}

/** Sanitize output by replacing known secret patterns */
function sanitizeOutput(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeOutput(item));
  }

  if (obj !== null && typeof obj === 'object') {
    const clone: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      clone[k] = sanitizeOutput(v);
    }
    return clone;
  }

  return obj;
}

function sanitizeString(input: string): string {
  let output = input;
  const replacements: [RegExp, string][] = [
    [/sk-ant-[a-zA-Z0-9_-]{20,}/g, '[REDACTED:anthropic_key]'],
    [/sk-[a-zA-Z0-9_-]{20,}/g, '[REDACTED:openai_key]'],
    [/AIza[a-zA-Z0-9_-]{35}/g, '[REDACTED:google_ai_key]'],
    [/AKIA[A-Z0-9]{16}/g, '[REDACTED:aws_key]'],
    [/gh[pos]_[a-zA-Z0-9]{20,}/g, '[REDACTED:github_token]'],
    [/xox[bpras]-[a-zA-Z0-9-]+/g, '[REDACTED:slack_token]'],
    [/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[REDACTED:jwt]'],
    [/Bearer [a-zA-Z0-9._-]+/g, '[REDACTED:bearer_token]'],
    [/(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/g, '[REDACTED:connection_string]'],
    [/(?:password|secret|api[_-]?key)\s*[=:]\s*['"]?[^\s'"]+/gi, '[REDACTED:generic_secret]'],
  ];

  for (const [pattern, replacement] of replacements) {
    output = output.replace(pattern, replacement);
  }

  return output;
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/** Error thrown when the Shell rejects a tool call */
export class ChitinToolRejectionError extends Error {
  public readonly toolName: string;
  public readonly actionType: string;
  public readonly rejectionReason: string;
  public readonly requiresHuman: boolean;

  constructor(
    toolName: string,
    actionType: string,
    reason: string,
    requiresHuman: boolean,
  ) {
    const message = requiresHuman
      ? `Tool '${toolName}' (action: ${actionType}) requires human approval: ${reason}`
      : `Tool '${toolName}' (action: ${actionType}) rejected by Chitin Shell: ${reason}`;

    super(message);
    this.name = 'ChitinToolRejectionError';
    this.toolName = toolName;
    this.actionType = actionType;
    this.rejectionReason = reason;
    this.requiresHuman = requiresHuman;
  }
}
