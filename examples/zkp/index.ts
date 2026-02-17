/**
 * ChitinShell ZKP Example
 *
 * Demonstrates how to use the ZKP (Zero-Knowledge Proof) framework
 * with ChitinShell for provenance tracking, non-leakage verification,
 * and skill safety analysis.
 *
 * Run: npx tsx examples/zkp/index.ts
 */

import { ChitinShell } from '@chitin-id/shell-core';
import type { ActionMapper, IVault } from '@chitin-id/shell-core';
import type { PolicyConfig } from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// Custom Mapper — simulates an email-sending action
// ---------------------------------------------------------------------------

class SendMessageMapper implements ActionMapper {
  readonly action_type = 'send_message';

  async execute(params: Record<string, unknown>): Promise<unknown> {
    return {
      sent: true,
      to: params.to,
      body: params.body,
      messageId: `msg-${Date.now()}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

const policy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only',
      actions: ['think', 'recall'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk write',
      actions: ['send_message'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk',
      actions: ['api_call'],
      verification: 'local',
    },
  },
  whitelists: {
    contacts: ['alice@example.com', 'bob@example.com'],
  },
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== ChitinShell ZKP Example ===\n');

  // 1. Create a shell with ZKP enabled
  const shell = await ChitinShell.create({
    policy,
    zkp: {
      enabled: true,
      provenance: true,   // Track prompt-to-intent derivation
      nonLeakage: true,   // Verify output does not leak vault secrets
      skillSafety: false,  // We'll enable this in example 3
    },
  });

  shell.registerMapper(new SendMessageMapper());

  console.log('Agent DID:', shell.getAgentDid());
  console.log('ZKP Prover:', shell.zkProver ? 'enabled' : 'disabled');
  console.log('ZKP Verifier:', shell.zkVerifier ? 'enabled' : 'disabled');

  // 2. Store a secret in the vault (should never appear in output)
  await shell.vault.set('api-key', {
    type: 'api_key',
    value: 'sk-secret-do-not-leak-1234567890',
  });
  console.log('\nVault: stored api-key secret\n');

  // 3. Execute with ZK proofs — provenance + non-leakage
  console.log('--- Example 1: Execute with Provenance + Non-Leakage ---');
  const prompt = 'Send a greeting message to alice@example.com';
  const intent = shell.createIntent({
    action: 'send_message',
    params: { to: 'alice@example.com', body: 'Hello, Alice!' },
  });

  const result = await shell.executeWithProof(intent, { prompt });

  console.log('Execution status:', result.execution?.status);
  console.log('Proof bundle generated:', !!result.proofBundle);

  if (result.proofBundle) {
    console.log('Combined hash:', result.proofBundle.combinedHash);

    if (result.proofBundle.provenance) {
      console.log('\nProvenance Proof:');
      console.log('  Prompt commitment:', result.proofBundle.provenance.promptCommitment);
      console.log('  Intent hash:', result.proofBundle.provenance.intentHash);
      console.log('  Derivation binding:', result.proofBundle.provenance.derivationBinding);

      // Verify the provenance proof
      const provenanceValid = await shell.zkVerifier!.verifyProvenanceProof(
        result.proofBundle.provenance,
      );
      console.log('  Verification:', provenanceValid ? 'VALID' : 'INVALID');
    }

    if (result.proofBundle.nonLeakage) {
      console.log('\nNon-Leakage Proof:');
      console.log('  Output hash:', result.proofBundle.nonLeakage.outputHash);
      console.log('  Vault entries checked:', result.proofBundle.nonLeakage.vaultEntryCount);
      console.log('  No leakage detected:', result.proofBundle.nonLeakage.verified);
    }
  }

  // 4. Execute without prompt — provenance skipped
  console.log('\n--- Example 2: Execute Without Prompt (no provenance) ---');
  const intent2 = shell.createIntent({
    action: 'send_message',
    params: { to: 'bob@example.com', body: 'Hey Bob!' },
  });

  const result2 = await shell.executeWithProof(intent2);
  console.log('Execution status:', result2.execution?.status);
  console.log('Provenance proof:', result2.proofBundle?.provenance ? 'generated' : 'skipped');
  console.log('Non-leakage proof:', result2.proofBundle?.nonLeakage ? 'generated' : 'skipped');

  // 5. Execute with skill safety analysis
  console.log('\n--- Example 3: Execute With Skill Safety Check ---');
  const shellWithSkillSafety = await ChitinShell.create({
    policy,
    zkp: {
      enabled: true,
      provenance: true,
      nonLeakage: true,
      skillSafety: true,
    },
  });
  shellWithSkillSafety.registerMapper(new SendMessageMapper());

  const safeSkillCode = `
export function greet(name) {
  return \`Hello, \${name}!\`;
}

export function formatMessage(to, body) {
  return { to, body, formatted: true };
}
`;

  const intent3 = shellWithSkillSafety.createIntent({
    action: 'send_message',
    params: { to: 'alice@example.com', body: 'Skill-generated greeting' },
  });

  const result3 = await shellWithSkillSafety.executeWithProof(intent3, {
    prompt: 'Use greeting skill for alice',
    skillCode: safeSkillCode,
  });

  console.log('Execution status:', result3.execution?.status);
  if (result3.proofBundle?.skillSafety) {
    console.log('\nSkill Safety Proof:');
    console.log('  Code hash:', result3.proofBundle.skillSafety.codeHash);
    console.log('  All checks passed:', result3.proofBundle.skillSafety.passed);
    console.log('  Checks performed:', result3.proofBundle.skillSafety.checks.length);
    for (const check of result3.proofBundle.skillSafety.checks) {
      console.log(`    ${check.passed ? 'PASS' : 'FAIL'}: ${check.name}`);
    }
  }

  // 6. Standard execute() still works (no proofs)
  console.log('\n--- Example 4: Standard execute() — no proofs ---');
  const intent4 = shell.createIntent({
    action: 'send_message',
    params: { to: 'alice@example.com', body: 'Standard message' },
  });
  const result4 = await shell.execute(intent4);
  console.log('Execution status:', result4.execution?.status);
  console.log('Proof bundle:', (result4 as Record<string, unknown>).proofBundle ?? 'none');

  console.log('\n=== Done ===');
}

main().catch(console.error);
