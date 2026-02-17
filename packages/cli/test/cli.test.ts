import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, writeFile, readFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadDefaultPolicy } from '@chitin-id/shell-core';

// We import `run` and test it by capturing console output.
// Commands that call process.exit() are handled via vi.spyOn.
import { run } from '../src/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let logs: string[] = [];
let errors: string[] = [];
let originalCwd: string;
let tempDir: string;

function captureOutput() {
  logs = [];
  errors = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logs.push(args.map(String).join(' '));
  });
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(' '));
  });
}

function allOutput(): string {
  return [...logs, ...errors].join('\n');
}

beforeEach(async () => {
  originalCwd = process.cwd();
  tempDir = await mkdtemp(join(tmpdir(), 'chitin-cli-test-'));
  process.chdir(tempDir);
  captureOutput();
  // Mock process.exit to throw instead
  vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
    throw new Error(`process.exit(${code})`);
  });
});

afterEach(async () => {
  process.chdir(originalCwd);
  vi.restoreAllMocks();
  await rm(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Help & Version
// ---------------------------------------------------------------------------

describe('help and version', () => {
  it('shows help with --help flag', async () => {
    await run(['--help']);
    const output = allOutput();
    expect(output).toContain('chitin-shell');
    expect(output).toContain('Commands:');
    expect(output).toContain('init');
    expect(output).toContain('policy');
    expect(output).toContain('logs');
    expect(output).toContain('vault');
  });

  it('shows help with -h flag', async () => {
    await run(['-h']);
    const output = allOutput();
    expect(output).toContain('chitin-shell');
  });

  it('shows help with no arguments', async () => {
    await run([]);
    const output = allOutput();
    expect(output).toContain('chitin-shell');
    expect(output).toContain('Commands:');
  });

  it('shows version with --version flag', async () => {
    await run(['--version']);
    expect(logs.join('\n')).toContain('0.1.0-alpha.0');
  });

  it('shows version with -v flag', async () => {
    await run(['-v']);
    expect(logs.join('\n')).toContain('0.1.0-alpha.0');
  });

  it('shows error for unknown command', async () => {
    await expect(run(['unknown-cmd'])).rejects.toThrow('process.exit(1)');
    expect(errors.join('\n')).toContain('Unknown command: unknown-cmd');
  });
});

// ---------------------------------------------------------------------------
// Init Command
// ---------------------------------------------------------------------------

describe('init command', () => {
  it('creates config files in current directory', async () => {
    await run(['init']);
    const output = allOutput();
    expect(output).toContain('Created chitin.config.json');
    expect(output).toContain('Created chitin-policy.json');

    // Verify files exist
    const configRaw = await readFile(join(tempDir, 'chitin.config.json'), 'utf-8');
    const config = JSON.parse(configRaw);
    expect(config.policy).toBe('chitin-policy.json');
    expect(config.auditDir).toBe('.chitin-shell/audit');

    const policyRaw = await readFile(join(tempDir, 'chitin-policy.json'), 'utf-8');
    const policy = JSON.parse(policyRaw);
    expect(policy.version).toBe('1.0');
    expect(policy.tiers.tier_0).toBeDefined();
    expect(policy.tiers.tier_3).toBeDefined();
  });

  it('does not overwrite existing files', async () => {
    // Create files first
    await writeFile(
      join(tempDir, 'chitin.config.json'),
      '{"existing":true}\n',
      'utf-8',
    );
    await writeFile(
      join(tempDir, 'chitin-policy.json'),
      '{"existing":true}\n',
      'utf-8',
    );

    await run(['init']);
    const output = allOutput();
    expect(output).toContain('already exists');
    expect(output).toContain('No files created');

    // Verify files were NOT overwritten
    const configRaw = await readFile(join(tempDir, 'chitin.config.json'), 'utf-8');
    expect(JSON.parse(configRaw)).toEqual({ existing: true });
  });

  it('shows getting-started instructions after successful init', async () => {
    await run(['init']);
    const output = allOutput();
    expect(output).toContain('Getting started');
    expect(output).toContain('chitin-shell policy verify');
  });
});

// ---------------------------------------------------------------------------
// Policy Commands
// ---------------------------------------------------------------------------

describe('policy commands', () => {
  it('policy show displays the default policy', async () => {
    await run(['policy', 'show']);
    const output = allOutput();
    expect(output).toContain('Security Policy');
    expect(output).toContain('TIER 0');
    expect(output).toContain('TIER 1');
    expect(output).toContain('TIER 2');
    expect(output).toContain('TIER 3');
    expect(output).toContain('think');
    expect(output).toContain('transfer_funds');
  });

  it('policy show reads from config file when available', async () => {
    // Init first
    await run(['init']);
    vi.restoreAllMocks();
    captureOutput();
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
      throw new Error(`process.exit(${code})`);
    });

    await run(['policy', 'show']);
    const output = allOutput();
    expect(output).toContain('Security Policy');
    expect(output).toContain('TIER 0');
  });

  it('policy show with --file reads from a specific file', async () => {
    const policyPath = join(tempDir, 'custom-policy.json');
    const customPolicy = loadDefaultPolicy();
    customPolicy.version = '2.0';
    await writeFile(policyPath, JSON.stringify(customPolicy), 'utf-8');

    await run(['policy', 'show', '--file', policyPath]);
    const output = allOutput();
    expect(output).toContain('Version: 2.0');
  });

  it('policy verify validates a valid policy', async () => {
    const policyPath = join(tempDir, 'valid-policy.json');
    const policy = loadDefaultPolicy();
    await writeFile(policyPath, JSON.stringify(policy), 'utf-8');

    await run(['policy', 'verify', '--file', policyPath]);
    const output = allOutput();
    expect(output).toContain('VALID');
    expect(output).not.toContain('INVALID');
  });

  it('policy verify catches invalid policy (missing tier)', async () => {
    const policyPath = join(tempDir, 'invalid-policy.json');
    const policy = {
      version: '1.0',
      tiers: {
        tier_0: {
          description: 'test',
          actions: ['think'],
          verification: 'none',
        },
        // Missing tier_1, tier_2, tier_3
      },
    };
    await writeFile(policyPath, JSON.stringify(policy), 'utf-8');

    // loadPolicyFromFile validates structure and will throw
    await expect(
      run(['policy', 'verify', '--file', policyPath]),
    ).rejects.toThrow('process.exit(1)');
    const output = allOutput();
    expect(output).toContain('INVALID');
  });

  it('policy verify catches invalid rate limit window format', async () => {
    const policyPath = join(tempDir, 'bad-rate-policy.json');
    const policy = loadDefaultPolicy();
    policy.tiers.tier_1.constraints = {
      rate_limit: { max: 10, window: 'invalid' },
    };
    await writeFile(policyPath, JSON.stringify(policy), 'utf-8');

    await expect(
      run(['policy', 'verify', '--file', policyPath]),
    ).rejects.toThrow('process.exit(1)');
    const output = allOutput();
    expect(output).toContain('INVALID');
    expect(output).toContain('window');
  });

  it('policy test shows tier 0 auto-approve for think', async () => {
    await run(['policy', 'test', 'think']);
    const output = allOutput();
    expect(output).toContain('Policy Test');
    expect(output).toContain('think');
    expect(output).toContain('TIER 0');
    expect(output).toContain('APPROVED');
  });

  it('policy test shows tier 3 human approval for transfer_funds', async () => {
    await run(['policy', 'test', 'transfer_funds']);
    const output = allOutput();
    expect(output).toContain('transfer_funds');
    expect(output).toContain('TIER 3');
    expect(output).toContain('REQUIRES HUMAN APPROVAL');
  });

  it('policy test shows tier for unknown actions (defaults to tier 3)', async () => {
    await run(['policy', 'test', 'custom_unknown_action']);
    const output = allOutput();
    expect(output).toContain('TIER 3');
    expect(output).toContain('REQUIRES HUMAN APPROVAL');
  });

  it('policy test with --to shows recipient', async () => {
    await run(['policy', 'test', 'send_message', '--to', 'alice@example.com']);
    const output = allOutput();
    expect(output).toContain('send_message');
    expect(output).toContain('alice@example.com');
    expect(output).toContain('TIER 1');
  });

  it('policy help is shown with no sub-command', async () => {
    await run(['policy']);
    const output = allOutput();
    expect(output).toContain('chitin-shell policy');
    expect(output).toContain('show');
    expect(output).toContain('verify');
    expect(output).toContain('test');
  });
});

// ---------------------------------------------------------------------------
// Logs Command
// ---------------------------------------------------------------------------

describe('logs command', () => {
  it('shows empty message when no audit logs exist', async () => {
    await run(['logs']);
    const output = allOutput();
    expect(output).toContain('No audit logs found');
  });

  it('displays audit entries from JSONL file', async () => {
    // Create audit directory and file
    const auditDir = join(tempDir, '.chitin-shell', 'audit');
    await mkdir(auditDir, { recursive: true });

    const entries = [
      {
        id: 'entry-1',
        timestamp: '2026-02-17T10:00:00.000Z',
        intent_id: 'intent-1',
        agent_did: 'did:key:test-agent',
        action_type: 'think',
        tier: 0,
        decision: 'approved',
        reason: 'Tier 0: auto-approved',
      },
      {
        id: 'entry-2',
        timestamp: '2026-02-17T10:01:00.000Z',
        intent_id: 'intent-2',
        agent_did: 'did:key:test-agent',
        action_type: 'transfer_funds',
        tier: 3,
        decision: 'rejected',
        reason: 'Requires human approval',
      },
    ];

    const jsonl = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await writeFile(join(auditDir, 'audit.jsonl'), jsonl, 'utf-8');

    await run(['logs']);
    const output = allOutput();
    expect(output).toContain('Audit Log');
    expect(output).toContain('think');
    expect(output).toContain('transfer_funds');
    expect(output).toContain('approved');
    expect(output).toContain('rejected');
  });

  it('filters audit entries with --last N', async () => {
    const auditDir = join(tempDir, '.chitin-shell', 'audit');
    await mkdir(auditDir, { recursive: true });

    const entries = Array.from({ length: 10 }, (_, i) => ({
      id: `entry-${i}`,
      timestamp: `2026-02-17T10:${String(i).padStart(2, '0')}:00.000Z`,
      intent_id: `intent-${i}`,
      agent_did: 'did:key:test-agent',
      action_type: 'think',
      tier: 0,
      decision: 'approved',
      reason: 'auto-approved',
    }));

    const jsonl = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await writeFile(join(auditDir, 'audit.jsonl'), jsonl, 'utf-8');

    await run(['logs', '--last', '3']);
    const output = allOutput();
    expect(output).toContain('Showing 3 entries');
  });

  it('filters audit entries with --action', async () => {
    const auditDir = join(tempDir, '.chitin-shell', 'audit');
    await mkdir(auditDir, { recursive: true });

    const entries = [
      {
        id: 'e1',
        timestamp: '2026-02-17T10:00:00Z',
        intent_id: 'i1',
        agent_did: 'did:key:a',
        action_type: 'think',
        tier: 0,
        decision: 'approved',
        reason: 'ok',
      },
      {
        id: 'e2',
        timestamp: '2026-02-17T10:01:00Z',
        intent_id: 'i2',
        agent_did: 'did:key:a',
        action_type: 'send_message',
        tier: 1,
        decision: 'approved',
        reason: 'ok',
      },
    ];

    const jsonl = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await writeFile(join(auditDir, 'audit.jsonl'), jsonl, 'utf-8');

    await run(['logs', '--action', 'think']);
    const output = allOutput();
    expect(output).toContain('Showing 1 entries');
    expect(output).toContain('think');
    expect(output).not.toContain('send_message');
  });

  it('filters audit entries with --decision', async () => {
    const auditDir = join(tempDir, '.chitin-shell', 'audit');
    await mkdir(auditDir, { recursive: true });

    const entries = [
      {
        id: 'e1',
        timestamp: '2026-02-17T10:00:00Z',
        intent_id: 'i1',
        agent_did: 'did:key:a',
        action_type: 'think',
        tier: 0,
        decision: 'approved',
        reason: 'ok',
      },
      {
        id: 'e2',
        timestamp: '2026-02-17T10:01:00Z',
        intent_id: 'i2',
        agent_did: 'did:key:a',
        action_type: 'transfer_funds',
        tier: 3,
        decision: 'rejected',
        reason: 'human required',
      },
    ];

    const jsonl = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    await writeFile(join(auditDir, 'audit.jsonl'), jsonl, 'utf-8');

    await run(['logs', '--decision', 'rejected']);
    const output = allOutput();
    expect(output).toContain('Showing 1 entries');
    expect(output).toContain('rejected');
  });
});

// ---------------------------------------------------------------------------
// Vault Commands
// ---------------------------------------------------------------------------

describe('vault commands', () => {
  it('vault list shows empty when no entries', async () => {
    await run(['vault', 'list']);
    const output = allOutput();
    expect(output).toContain('No vault entries found');
  });

  it('vault set adds a new entry and vault list shows it', async () => {
    await run(['vault', 'set', 'my-api-key', '--type', 'api_key', '--value', 'sk-1234']);
    expect(allOutput()).toContain('Added vault entry: my-api-key');

    // Reset output and check list
    vi.restoreAllMocks();
    captureOutput();
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
      throw new Error(`process.exit(${code})`);
    });

    await run(['vault', 'list']);
    const output = allOutput();
    expect(output).toContain('my-api-key');
    expect(output).toContain('api_key');
    // Values should NOT be displayed
    expect(output).not.toContain('sk-1234');
  });

  it('vault set updates an existing entry', async () => {
    await run(['vault', 'set', 'token', '--type', 'bearer', '--value', 'v1']);
    expect(allOutput()).toContain('Added vault entry: token');

    vi.restoreAllMocks();
    captureOutput();
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
      throw new Error(`process.exit(${code})`);
    });

    await run(['vault', 'set', 'token', '--type', 'bearer', '--value', 'v2']);
    expect(allOutput()).toContain('Updated vault entry: token');
  });

  it('vault delete removes an entry', async () => {
    // Set first
    await run(['vault', 'set', 'temp-key', '--type', 'api_key', '--value', 'val']);

    vi.restoreAllMocks();
    captureOutput();
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
      throw new Error(`process.exit(${code})`);
    });

    await run(['vault', 'delete', 'temp-key']);
    expect(allOutput()).toContain('Deleted vault entry: temp-key');

    // Verify it's gone from list
    vi.restoreAllMocks();
    captureOutput();
    vi.spyOn(process, 'exit').mockImplementation((code?: number | string | null | undefined) => {
      throw new Error(`process.exit(${code})`);
    });

    await run(['vault', 'list']);
    expect(allOutput()).toContain('No vault entries found');
  });

  it('vault delete fails for non-existent key', async () => {
    await expect(
      run(['vault', 'delete', 'non-existent']),
    ).rejects.toThrow('process.exit(1)');
    expect(errors.join('\n')).toContain('not found');
  });

  it('vault set rejects invalid type', async () => {
    await expect(
      run(['vault', 'set', 'key', '--type', 'invalid', '--value', 'val']),
    ).rejects.toThrow('process.exit(1)');
    expect(errors.join('\n')).toContain('Invalid type');
  });

  it('vault set requires --value', async () => {
    await expect(
      run(['vault', 'set', 'key', '--type', 'api_key']),
    ).rejects.toThrow('process.exit(1)');
    expect(errors.join('\n')).toContain('Missing --value');
  });

  it('vault help is shown with no sub-command', async () => {
    await run(['vault']);
    const output = allOutput();
    expect(output).toContain('chitin-shell vault');
    expect(output).toContain('list');
    expect(output).toContain('set');
    expect(output).toContain('delete');
  });
});
