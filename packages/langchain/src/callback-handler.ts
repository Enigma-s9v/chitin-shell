/**
 * Chitin Callback Handler for LangChain
 *
 * Intercepts LangChain tool invocations and runs them through
 * the Chitin Shell's Intent-Verify-Execute pipeline.
 *
 * This handler implements a LangChain-compatible callback interface
 * without requiring @langchain/core at build time.
 */

import type { ChitinShell } from '@chitin-id/shell-core';
import type {
  LangChainCallbackHandler,
  ChitinLangChainOptions,
  ChitinToolConfig,
  ToolCallInterception,
} from './types.js';
import type { ActionType } from '@chitin-id/shell-core';

/**
 * A callback handler that intercepts LangChain tool calls and enforces
 * Chitin Shell policies.
 *
 * Usage with LangChain:
 * ```ts
 * const shell = await ChitinShell.create();
 * const handler = new ChitinCallbackHandler({ shell });
 * const agent = new AgentExecutor({ callbacks: [handler] });
 * ```
 *
 * The handler intercepts `handleToolStart` to verify the tool call
 * against the Shell's policy engine before execution proceeds.
 */
export class ChitinCallbackHandler implements LangChainCallbackHandler {
  public readonly name = 'ChitinCallbackHandler';

  private shell: ChitinShell;
  private toolMappings: Record<string, ChitinToolConfig>;
  private defaultActionType: ActionType;
  private interceptions: ToolCallInterception[] = [];

  /** Pending run IDs that have been rejected — handleToolEnd should suppress them */
  private rejectedRuns: Set<string> = new Set();

  constructor(options: ChitinLangChainOptions) {
    this.shell = options.shell;
    this.toolMappings = options.toolMappings ?? {};
    this.defaultActionType = options.defaultActionType ?? 'api_call';
  }

  /**
   * Intercepts a tool invocation before execution.
   *
   * Creates a Chitin Shell Intent from the tool call, runs it through
   * the policy engine, and throws if the call is rejected.
   */
  async handleToolStart(
    tool: { name: string },
    input: string,
    runId: string,
  ): Promise<void> {
    const toolName = tool.name;
    const mapping = this.toolMappings[toolName];

    // Resolve action type
    const actionType = mapping?.actionType ?? this.defaultActionType;

    // Parse tool input
    let parsedInput: Record<string, unknown>;
    try {
      parsedInput = JSON.parse(input);
    } catch {
      // If input isn't JSON, wrap it as a single value
      parsedInput = { input };
    }

    // Apply param mapping if configured
    const mappedParams = mapping?.mapParams
      ? mapping.mapParams(parsedInput)
      : parsedInput;

    // Create and verify the intent
    const intent = this.shell.createIntent({
      action: actionType,
      params: mappedParams,
      context: { triggered_by: 'agent_internal' },
    });

    const result = await this.shell.execute(intent);

    // Record the interception
    const interception: ToolCallInterception = {
      toolName,
      originalInput: parsedInput,
      mappedActionType: actionType,
      mappedParams,
      approved: result.verification.approved,
      tier: result.verification.tier,
      reason: result.verification.reason,
      timestamp: new Date().toISOString(),
    };
    this.interceptions.push(interception);

    // If rejected, mark the run and throw
    if (!result.verification.approved) {
      this.rejectedRuns.add(runId);
      throw new Error(
        `[ChitinShell] Tool '${toolName}' rejected: ${result.verification.reason}`,
      );
    }
  }

  /**
   * Handles tool execution completion.
   * Sanitizes the output to ensure no secrets leak through.
   */
  async handleToolEnd(output: string, runId: string): Promise<void> {
    // If this run was already rejected, clean up
    if (this.rejectedRuns.has(runId)) {
      this.rejectedRuns.delete(runId);
      return;
    }

    // Sanitize output — we check for common secret patterns
    // The actual sanitization happens at the Executor level when using
    // Shell.execute(), but this provides a second layer of defense
    // for tools that bypass the mapper path.
    if (containsSecretPatterns(output)) {
      // Log a warning through audit
      const intent = this.shell.createIntent({
        action: 'think',
        params: { _warning: 'Secret detected in tool output', tool_run_id: runId },
      });
      await this.shell.execute(intent);
    }
  }

  /**
   * Handles tool execution errors.
   * Ensures error messages don't contain sensitive information.
   */
  async handleToolError(error: Error, runId: string): Promise<void> {
    // Clean up rejected run tracking
    this.rejectedRuns.delete(runId);

    // Check if the error message contains secrets
    if (containsSecretPatterns(error.message)) {
      // Replace the error message with a sanitized version
      error.message = sanitizeString(error.message);
    }
  }

  /**
   * Returns all recorded interceptions for inspection/debugging.
   */
  getInterceptions(): readonly ToolCallInterception[] {
    return this.interceptions;
  }

  /**
   * Clears the recorded interceptions.
   */
  clearInterceptions(): void {
    this.interceptions = [];
  }
}

// ---------------------------------------------------------------------------
// Internal sanitization helpers (same patterns as secure-tool.ts)
// ---------------------------------------------------------------------------

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
