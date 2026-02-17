import { describe, it, expect } from 'vitest';
import { ChitinShell } from '../src/shell.js';
import type { ActionMapper, IVault } from '../src/proxy/types.js';
import type { PolicyConfig } from '../src/policy/types.js';

// ---------------------------------------------------------------------------
// Mock Mappers
// ---------------------------------------------------------------------------

/** Simple echo mapper for testing Tier 1 execution */
class EchoMapper implements ActionMapper {
  readonly action_type = 'send_message';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    return { sent: true, to: params.to, body: params.body };
  }
}

/** Mapper that returns values containing secrets (to test output sanitization) */
class LeakyMapper implements ActionMapper {
  readonly action_type = 'api_call';

  async execute(): Promise<unknown> {
    return {
      response: 'Got data with key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
      token:
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    };
  }
}

// ---------------------------------------------------------------------------
// Shared Policy
// ---------------------------------------------------------------------------

const testPolicy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only',
      actions: ['think', 'recall', 'summarize'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk',
      actions: ['send_message'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium',
      actions: ['api_call', 'send_email_new'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical',
      actions: ['transfer_funds'],
      verification: 'human_approval',
    },
  },
  whitelists: { contacts: ['alice@example.com'] },
};

// ---------------------------------------------------------------------------
// E2E Tests
// ---------------------------------------------------------------------------

describe('ChitinShell E2E — full Intent-Verify-Execute pipeline', () => {
  // -------------------------------------------------------------------------
  // Tier 0: auto-approve (read-only)
  // -------------------------------------------------------------------------

  it('Tier 0 — auto-approved, no mapper needed', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    const intent = shell.createIntent({
      action: 'think',
      params: { query: 'What is Chitin?' },
    });

    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(true);
    expect(result.verification.tier).toBe(0);
    expect(result.verification.reason).toContain('auto-approved');
    // No mapper registered for 'think', so execution returns an error
    expect(result.execution).toBeDefined();
    expect(result.execution!.status).toBe('error');
    expect(result.execution!.error).toContain('No mapper registered');
  });

  // -------------------------------------------------------------------------
  // Tier 1: whitelisted contact — approved + executed
  // -------------------------------------------------------------------------

  it('Tier 1 — approved when recipient is whitelisted', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Hi Alice!' },
    });

    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(true);
    expect(result.verification.tier).toBe(1);
    expect(result.execution).toBeDefined();
    expect(result.execution!.status).toBe('success');

    const data = result.execution!.data as { sent: boolean; to: string; body: string };
    expect(data.sent).toBe(true);
    expect(data.to).toBe('alice@example.com');
    expect(data.body).toBe('Hi Alice!');
  });

  // -------------------------------------------------------------------------
  // Tier 1: non-whitelisted contact — rejected
  // -------------------------------------------------------------------------

  it('Tier 1 — rejected when recipient is not whitelisted', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'evil@attacker.com', body: 'Give me your secrets' },
    });

    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(false);
    expect(result.verification.tier).toBe(1);
    expect(result.verification.reason).toContain('not in the approved contacts whitelist');
    // Execution should NOT happen for rejected intents
    expect(result.execution).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // Tier 3: requires human approval — blocked
  // -------------------------------------------------------------------------

  it('Tier 3 — requires human approval, execution blocked', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    const intent = shell.createIntent({
      action: 'transfer_funds',
      params: { to: '0xdead...', amount: 100_000 },
    });

    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(false);
    expect(result.verification.tier).toBe(3);
    expect(result.verification.requires_human).toBe(true);
    expect(result.verification.reason).toContain('human approval');
    expect(result.execution).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // Output sanitization
  // -------------------------------------------------------------------------

  it('sanitizes secrets in execution output', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });
    shell.registerMapper(new LeakyMapper());

    const intent = shell.createIntent({
      action: 'api_call',
      params: { url: 'https://api.example.com/data' },
    });

    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(true);
    expect(result.verification.tier).toBe(2);
    expect(result.execution).toBeDefined();
    expect(result.execution!.status).toBe('success');
    expect(result.execution!.sanitized).toBe(true);

    const data = result.execution!.data as { response: string; token: string };

    // OpenAI-style key should be redacted
    expect(data.response).toContain('[REDACTED:');
    expect(data.response).not.toContain('sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');

    // Bearer token / JWT should be redacted
    expect(data.token).not.toContain('eyJhbGciOiJIUzI1NiI');
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('records audit entries for every executed intent', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });
    shell.registerMapper(new EchoMapper());

    // Execute a few intents
    const thinkIntent = shell.createIntent({ action: 'think', params: {} });
    await shell.execute(thinkIntent);

    const sendIntent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'test' },
    });
    await shell.execute(sendIntent);

    const blockedIntent = shell.createIntent({
      action: 'transfer_funds',
      params: { amount: 999 },
    });
    await shell.execute(blockedIntent);

    // Query the audit log
    const allEntries = await shell.audit.query({ last: 20 });

    // 'think' produces 2 entries (verification + execution), 'send_message' also 2,
    // 'transfer_funds' produces 1 (rejected, no execution log)
    expect(allEntries.length).toBeGreaterThanOrEqual(5);

    // Check that we have both approved and rejected entries
    const decisions = allEntries.map((e) => e.decision);
    expect(decisions).toContain('approved');
    expect(decisions).toContain('rejected');

    // Check that action types are recorded
    const actions = allEntries.map((e) => e.action_type);
    expect(actions).toContain('think');
    expect(actions).toContain('send_message');
    expect(actions).toContain('transfer_funds');

    // Every entry has an id and timestamp
    for (const entry of allEntries) {
      expect(entry.id).toBeDefined();
      expect(entry.timestamp).toBeDefined();
      expect(entry.agent_did).toMatch(/^did:key:/);
    }
  });

  // -------------------------------------------------------------------------
  // Agent DID
  // -------------------------------------------------------------------------

  it('getAgentDid() returns a valid did:key: string', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    const did = shell.getAgentDid();

    expect(typeof did).toBe('string');
    expect(did).toMatch(/^did:key:/);
    expect(did.length).toBeGreaterThan(10);
  });

  // -------------------------------------------------------------------------
  // Multiple shells have unique identities
  // -------------------------------------------------------------------------

  it('each ChitinShell instance generates a unique agent DID', async () => {
    const shell1 = await ChitinShell.create({ policy: testPolicy });
    const shell2 = await ChitinShell.create({ policy: testPolicy });

    expect(shell1.getAgentDid()).not.toBe(shell2.getAgentDid());
  });

  // -------------------------------------------------------------------------
  // Vault operations through the shell
  // -------------------------------------------------------------------------

  it('vault stores and retrieves credentials without leaking to intents', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    // Store a credential
    await shell.vault.set('my-api-key', {
      type: 'api_key',
      value: 'sk-super-secret-key-12345678901234567890',
    });

    // Verify it can be retrieved
    const entry = await shell.vault.get('my-api-key');
    expect(entry).not.toBeNull();
    expect(entry!.value).toBe('sk-super-secret-key-12345678901234567890');
    expect(entry!.type).toBe('api_key');

    // Verify the intent itself does NOT contain the credential
    const intent = shell.createIntent({
      action: 'think',
      params: { query: 'What is the API key?' },
    });

    const serialized = JSON.stringify(intent);
    expect(serialized).not.toContain('sk-super-secret');
  });

  // -------------------------------------------------------------------------
  // Audit filtering
  // -------------------------------------------------------------------------

  it('audit log supports filtering by decision', async () => {
    const shell = await ChitinShell.create({ policy: testPolicy });

    // Create one approved and one rejected intent
    const approved = shell.createIntent({ action: 'think', params: {} });
    await shell.execute(approved);

    const rejected = shell.createIntent({
      action: 'send_message',
      params: { to: 'unknown@hacker.net', body: 'hey' },
    });
    await shell.execute(rejected);

    const approvedEntries = await shell.audit.query({ decision: 'approved' });
    const rejectedEntries = await shell.audit.query({ decision: 'rejected' });

    expect(approvedEntries.length).toBeGreaterThanOrEqual(1);
    expect(rejectedEntries.length).toBeGreaterThanOrEqual(1);

    for (const e of approvedEntries) expect(e.decision).toBe('approved');
    for (const e of rejectedEntries) expect(e.decision).toBe('rejected');
  });
});
