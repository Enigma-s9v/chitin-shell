import { describe, it, expect, beforeEach } from 'vitest';
import { ChitinShell } from '../src/shell.js';
import type { ActionMapper } from '../src/proxy/types.js';
import type { PolicyConfig } from '../src/policy/types.js';
import type { ZkProofBundle } from '../src/zkp/types.js';

// ---------------------------------------------------------------------------
// Mock Mappers
// ---------------------------------------------------------------------------

class EchoMapper implements ActionMapper {
  readonly action_type = 'send_message';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    return { sent: true, to: params.to, body: params.body };
  }
}

class DataMapper implements ActionMapper {
  readonly action_type = 'api_call';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    return { data: params.query ?? 'result', status: 200 };
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
      actions: ['api_call'],
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
// ZKP Integration Tests
// ---------------------------------------------------------------------------

describe('ChitinShell ZKP Integration', () => {
  // -------------------------------------------------------------------------
  // Shell creation with ZKP
  // -------------------------------------------------------------------------

  it('creates prover and verifier when zkp is enabled', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true },
    });

    expect(shell.zkProver).toBeDefined();
    expect(shell.zkVerifier).toBeDefined();
  });

  it('does not create prover/verifier when zkp is disabled', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: false },
    });

    expect(shell.zkProver).toBeUndefined();
    expect(shell.zkVerifier).toBeUndefined();
  });

  it('does not create prover/verifier when zkp option is omitted', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
    });

    expect(shell.zkProver).toBeUndefined();
    expect(shell.zkVerifier).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // executeWithProof — provenance
  // -------------------------------------------------------------------------

  it('executeWithProof generates provenance proof when prompt provided', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Hello!' },
    });

    const result = await shell.executeWithProof(intent, {
      prompt: 'Send a greeting to alice',
    });

    expect(result.verification.approved).toBe(true);
    expect(result.execution).toBeDefined();
    expect(result.execution!.status).toBe('success');
    expect(result.proofBundle).toBeDefined();
    expect(result.proofBundle!.provenance).toBeDefined();
    expect(result.proofBundle!.provenance!.promptCommitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.proofBundle!.provenance!.intentHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  // -------------------------------------------------------------------------
  // executeWithProof — non-leakage
  // -------------------------------------------------------------------------

  it('executeWithProof generates non-leakage proof for output', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new DataMapper());

    // Store a secret in vault
    await shell.vault.set('api-key', { type: 'api_key', value: 'sk-secret-vault-key-1234567890' });

    const intent = shell.createIntent({
      action: 'api_call',
      params: { query: 'safe data' },
    });

    const result = await shell.executeWithProof(intent);

    expect(result.proofBundle).toBeDefined();
    expect(result.proofBundle!.nonLeakage).toBeDefined();
    expect(result.proofBundle!.nonLeakage!.outputHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.proofBundle!.nonLeakage!.verified).toBe(true);
    expect(result.proofBundle!.nonLeakage!.vaultEntryCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // executeWithProof — skips proofs when zkp disabled
  // -------------------------------------------------------------------------

  it('executeWithProof skips proofs when zkp is disabled', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Hello!' },
    });

    const result = await shell.executeWithProof(intent, {
      prompt: 'Greeting prompt',
    });

    expect(result.verification.approved).toBe(true);
    expect(result.execution).toBeDefined();
    expect(result.proofBundle).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // combinedHash consistency
  // -------------------------------------------------------------------------

  it('proof bundle combinedHash is consistent', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Test' },
    });

    const result = await shell.executeWithProof(intent, {
      prompt: 'Test prompt',
    });

    expect(result.proofBundle).toBeDefined();
    expect(result.proofBundle!.combinedHash).toBeDefined();
    expect(result.proofBundle!.combinedHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  // -------------------------------------------------------------------------
  // Audit log records proof generation
  // -------------------------------------------------------------------------

  it('audit log records proof generation entry', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Hi' },
    });

    await shell.executeWithProof(intent, { prompt: 'Say hi' });

    const entries = await shell.audit.query({ last: 20 });
    const proofEntry = entries.find((e) => e.reason === 'proof_generated');

    expect(proofEntry).toBeDefined();
    expect(proofEntry!.action_type).toBe('send_message');
    expect(proofEntry!.decision).toBe('approved');
  });

  // -------------------------------------------------------------------------
  // executeWithProof with skillCode
  // -------------------------------------------------------------------------

  it('executeWithProof with skillCode generates skill safety proof', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true, skillSafety: true },
    });
    shell.registerMapper(new EchoMapper());

    const skillCode = `
export function greet(name) {
  return \`Hello, \${name}!\`;
}
`;

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Greet!' },
    });

    const result = await shell.executeWithProof(intent, {
      prompt: 'Run greeting skill',
      skillCode,
    });

    expect(result.proofBundle).toBeDefined();
    expect(result.proofBundle!.skillSafety).toBeDefined();
    expect(result.proofBundle!.skillSafety!.codeHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.proofBundle!.skillSafety!.passed).toBe(true);
  });

  // -------------------------------------------------------------------------
  // Verifier can verify the generated bundle
  // -------------------------------------------------------------------------

  it('verifier can verify the generated bundle', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Verify me' },
    });

    const result = await shell.executeWithProof(intent, {
      prompt: 'Verification test prompt',
    });

    expect(result.proofBundle).toBeDefined();

    // Verify provenance proof
    if (result.proofBundle!.provenance) {
      const provenanceValid = await shell.zkVerifier!.verifyProvenanceProof(
        result.proofBundle!.provenance,
      );
      expect(provenanceValid).toBe(true);
    }
  });

  // -------------------------------------------------------------------------
  // executeWithProof without prompt skips provenance
  // -------------------------------------------------------------------------

  it('executeWithProof without prompt skips provenance proof', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new DataMapper());

    // Store a vault entry for non-leakage check
    await shell.vault.set('token', { type: 'bearer', value: 'bearer-secret-123' });

    const intent = shell.createIntent({
      action: 'api_call',
      params: { query: 'lookup' },
    });

    // Execute without prompt
    const result = await shell.executeWithProof(intent);

    expect(result.proofBundle).toBeDefined();
    // Provenance should be undefined since no prompt was provided
    expect(result.proofBundle!.provenance).toBeUndefined();
    // Non-leakage should still be generated
    expect(result.proofBundle!.nonLeakage).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Existing execute() still works normally with zkp enabled
  // -------------------------------------------------------------------------

  it('existing execute() works normally even when zkp is enabled', async () => {
    const shell = await ChitinShell.create({
      policy: testPolicy,
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    });
    shell.registerMapper(new EchoMapper());

    const intent = shell.createIntent({
      action: 'send_message',
      params: { to: 'alice@example.com', body: 'Normal execute' },
    });

    // Use the standard execute (not executeWithProof)
    const result = await shell.execute(intent);

    expect(result.verification.approved).toBe(true);
    expect(result.execution).toBeDefined();
    expect(result.execution!.status).toBe('success');
    // No proof bundle on standard execute
    expect((result as Record<string, unknown>).proofBundle).toBeUndefined();
  });
});
