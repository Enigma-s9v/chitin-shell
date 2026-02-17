/**
 * Chitin Shell — Basic Usage Example
 *
 * This demonstrates the Intent-Verify-Execute pipeline:
 * 1. LLM produces structured Intents (NOT raw API calls)
 * 2. Policy Engine verifies against rules
 * 3. Secure Proxy executes with credentials the LLM never sees
 *
 * Run with:  npx tsx examples/basic/index.ts
 */

import { ChitinShell } from '../../packages/core/src/index.js';
import type { ActionMapper, PolicyConfig } from '../../packages/core/src/index.js';

// ---------------------------------------------------------------------------
// 1. Define a Policy
// ---------------------------------------------------------------------------
// Policies are deterministic rules — no LLM involved.
// They define which actions are auto-approved, which need checks, and which
// require a human to sign off.

const policy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only & internal (auto-approved)',
      actions: ['think', 'recall', 'summarize'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk writes (whitelisted contacts only)',
      actions: ['send_message', 'reply_email'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk operations',
      actions: ['api_call', 'send_email_new'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical — requires human approval',
      actions: ['transfer_funds', 'change_permissions'],
      verification: 'human_approval',
    },
  },
  whitelists: {
    contacts: ['alice@example.com', 'bob@example.com'],
  },
};

// ---------------------------------------------------------------------------
// 2. Define a Custom Action Mapper
// ---------------------------------------------------------------------------
// Mappers bridge the gap between abstract Intents and real-world side effects.
// The LLM never calls APIs directly — it produces Intents, and mappers do
// the actual work.

class EchoMessenger implements ActionMapper {
  readonly action_type = 'send_message';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    // In a real app, this would call Slack, Discord, email, etc.
    return {
      sent: true,
      to: params.to,
      body: params.body,
      delivered_at: new Date().toISOString(),
    };
  }
}

class MockApiCaller implements ActionMapper {
  readonly action_type = 'api_call';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    // Simulate an API response that accidentally contains secrets
    return {
      status: 200,
      url: params.url,
      data: 'Response contains key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      auth_header:
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    };
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== Chitin Shell — Basic Usage Example ===\n');

  // 3. Create the shell instance
  const shell = await ChitinShell.create({ policy });

  console.log(`Agent DID: ${shell.getAgentDid()}\n`);

  // 4. Register mappers
  shell.registerMapper(new EchoMessenger());
  shell.registerMapper(new MockApiCaller());

  // 5. Store a credential in the vault
  //    The LLM never has access to these values.
  await shell.vault.set('slack-bot-token', {
    type: 'bearer',
    value: 'xoxb-not-a-real-token-1234567890',
  });

  console.log('Vault keys:', await shell.vault.list());
  console.log();

  // -----------------------------------------------------------------------
  // Example A: Tier 0 — Read-only (auto-approved)
  // -----------------------------------------------------------------------
  console.log('--- Example A: Tier 0 (think) ---');

  const thinkIntent = shell.createIntent({
    action: 'think',
    params: { query: 'What are the benefits of SBTs for AI agents?' },
  });

  const thinkResult = await shell.execute(thinkIntent);

  console.log(`  Tier:     ${thinkResult.verification.tier}`);
  console.log(`  Approved: ${thinkResult.verification.approved}`);
  console.log(`  Reason:   ${thinkResult.verification.reason}`);
  console.log();

  // -----------------------------------------------------------------------
  // Example B: Tier 1 — Send message to whitelisted contact (approved)
  // -----------------------------------------------------------------------
  console.log('--- Example B: Tier 1 (send_message to whitelisted contact) ---');

  const sendIntent = shell.createIntent({
    action: 'send_message',
    params: { to: 'alice@example.com', body: 'Hey Alice, the deploy is done!' },
  });

  const sendResult = await shell.execute(sendIntent);

  console.log(`  Tier:     ${sendResult.verification.tier}`);
  console.log(`  Approved: ${sendResult.verification.approved}`);
  console.log(`  Reason:   ${sendResult.verification.reason}`);
  if (sendResult.execution) {
    console.log(`  Status:   ${sendResult.execution.status}`);
    console.log(`  Data:     ${JSON.stringify(sendResult.execution.data)}`);
    console.log(`  Time:     ${sendResult.execution.execution_time_ms}ms`);
  }
  console.log();

  // -----------------------------------------------------------------------
  // Example C: Tier 1 — Send message to unknown contact (rejected)
  // -----------------------------------------------------------------------
  console.log('--- Example C: Tier 1 (send_message to non-whitelisted contact) ---');

  const blockedSend = shell.createIntent({
    action: 'send_message',
    params: { to: 'hacker@evil.com', body: 'Here are the passwords...' },
  });

  const blockedResult = await shell.execute(blockedSend);

  console.log(`  Tier:     ${blockedResult.verification.tier}`);
  console.log(`  Approved: ${blockedResult.verification.approved}`);
  console.log(`  Reason:   ${blockedResult.verification.reason}`);
  console.log(`  Executed: ${blockedResult.execution !== undefined}`);
  console.log();

  // -----------------------------------------------------------------------
  // Example D: Tier 3 — Transfer funds (requires human approval)
  // -----------------------------------------------------------------------
  console.log('--- Example D: Tier 3 (transfer_funds) ---');

  const transferIntent = shell.createIntent({
    action: 'transfer_funds',
    params: { to: '0x1234...abcd', amount: 50_000, currency: 'USDC' },
  });

  const transferResult = await shell.execute(transferIntent);

  console.log(`  Tier:           ${transferResult.verification.tier}`);
  console.log(`  Approved:       ${transferResult.verification.approved}`);
  console.log(`  Requires Human: ${transferResult.verification.requires_human}`);
  console.log(`  Reason:         ${transferResult.verification.reason}`);
  console.log(`  Executed:       ${transferResult.execution !== undefined}`);
  console.log();

  // -----------------------------------------------------------------------
  // Example E: Output Sanitization
  // -----------------------------------------------------------------------
  console.log('--- Example E: Output Sanitization ---');

  const apiIntent = shell.createIntent({
    action: 'api_call',
    params: { url: 'https://api.example.com/data' },
  });

  const apiResult = await shell.execute(apiIntent);

  console.log(`  Sanitized: ${apiResult.execution?.sanitized}`);
  console.log(`  Data:      ${JSON.stringify(apiResult.execution?.data, null, 2)}`);
  console.log();
  console.log('  ^ Notice: API keys and JWTs have been replaced with [REDACTED:...]');
  console.log();

  // -----------------------------------------------------------------------
  // Example F: Audit Log
  // -----------------------------------------------------------------------
  console.log('--- Example F: Audit Log ---');

  const auditEntries = await shell.audit.query({ last: 10 });

  console.log(`  Total entries: ${auditEntries.length}\n`);

  for (const entry of auditEntries) {
    console.log(
      `  [${entry.timestamp}] ${entry.action_type.padEnd(16)} ${entry.decision.padEnd(10)} ${entry.reason.slice(0, 60)}`,
    );
  }

  console.log('\n=== Done ===');
}

main().catch(console.error);
