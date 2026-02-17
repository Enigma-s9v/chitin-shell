/**
 * Chitin Shell — LangChain Integration Example
 *
 * This demonstrates how to wrap LangChain tools with Chitin Shell
 * so every tool call goes through Intent-Verify-Execute.
 *
 * Run with:  npx tsx examples/langchain/index.ts
 */

import { ChitinShell } from '../../packages/core/src/index.js';
import { createSecureTool } from '../../packages/langchain/src/index.js';
import type { PolicyConfig } from '../../packages/core/src/index.js';
import type { ToolDefinition } from '../../packages/langchain/src/index.js';

// ---------------------------------------------------------------------------
// 1. Policy — same as any Chitin Shell setup
// ---------------------------------------------------------------------------

const policy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only',
      actions: ['think', 'recall', 'summarize', 'web_search'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk writes',
      actions: ['send_message', 'reply_email'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk',
      actions: ['api_call', 'write_file'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical',
      actions: ['transfer_funds', 'delete_user'],
      verification: 'human_approval',
    },
  },
  whitelists: { contacts: ['team@example.com'] },
};

// ---------------------------------------------------------------------------
// 2. Define LangChain-style tools
// ---------------------------------------------------------------------------

const searchTool: ToolDefinition = {
  name: 'web_search',
  description: 'Search the web for information',
  async execute(input) {
    return { results: [`Result for: ${input.query}`] };
  },
};

const emailTool: ToolDefinition = {
  name: 'send_email',
  description: 'Send an email',
  async execute(input) {
    return { sent: true, to: input.to, subject: input.subject };
  },
};

const dangerousTool: ToolDefinition = {
  name: 'delete_user',
  description: 'Delete a user account',
  async execute(input) {
    return { deleted: true, userId: input.userId };
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== Chitin Shell + LangChain Example ===\n');

  const shell = await ChitinShell.create({ policy });

  // 3. Wrap tools with Chitin Shell security
  const secureSearch = createSecureTool(searchTool, { shell });
  const secureEmail = createSecureTool(emailTool, {
    shell,
    actionType: 'send_message',  // map to tier 1
  });
  const secureDangerous = createSecureTool(dangerousTool, { shell });

  // 4. Use wrapped tools — they look the same but are secure

  // A: Search — Tier 0, auto-approved
  console.log('--- A: web_search (Tier 0) ---');
  try {
    const searchResult = await secureSearch.execute({ query: 'AI agent security' });
    console.log('  Result:', JSON.stringify(searchResult));
  } catch (e) {
    console.log('  Blocked:', (e as Error).message);
  }
  console.log();

  // B: Email to whitelisted contact — Tier 1, approved
  console.log('--- B: send_email to whitelisted (Tier 1) ---');
  try {
    const emailResult = await secureEmail.execute({
      to: 'team@example.com',
      subject: 'Deploy complete',
    });
    console.log('  Result:', JSON.stringify(emailResult));
  } catch (e) {
    console.log('  Blocked:', (e as Error).message);
  }
  console.log();

  // C: Email to unknown contact — Tier 1, rejected
  console.log('--- C: send_email to non-whitelisted (Tier 1) ---');
  try {
    const emailResult = await secureEmail.execute({
      to: 'hacker@evil.com',
      subject: 'Here are the passwords',
    });
    console.log('  Result:', JSON.stringify(emailResult));
  } catch (e) {
    console.log('  Blocked:', (e as Error).message);
  }
  console.log();

  // D: Dangerous action — Tier 3, requires human approval
  console.log('--- D: delete_user (Tier 3) ---');
  try {
    const deleteResult = await secureDangerous.execute({ userId: 'user-123' });
    console.log('  Result:', JSON.stringify(deleteResult));
  } catch (e) {
    console.log('  Blocked:', (e as Error).message);
  }

  console.log('\n=== Done ===');
}

main().catch(console.error);
