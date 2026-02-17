/**
 * `chitin-shell vault` — Vault management sub-commands
 *
 * - list   : List all vault keys (NOT values)
 * - set    : Set a vault entry
 * - delete : Delete a vault entry
 *
 * Uses an in-memory vault for demonstration. In production, this would be
 * backed by a persistent keychain or TEE-backed store.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { color, parseFlag, loadConfig } from '../utils.js';

// ---------------------------------------------------------------------------
// File-backed vault storage (keys + types only, values encrypted)
// ---------------------------------------------------------------------------

interface VaultManifestEntry {
  type: string;
  created_at: string;
}

type VaultManifest = Record<string, VaultManifestEntry>;

async function getVaultDir(cwd?: string): Promise<string> {
  const dir = cwd ?? process.cwd();
  try {
    const config = await loadConfig(dir);
    return join(dir, config.auditDir, '..', 'vault');
  } catch {
    return join(dir, '.chitin-shell', 'vault');
  }
}

async function loadManifest(vaultDir: string): Promise<VaultManifest> {
  const manifestPath = join(vaultDir, 'manifest.json');
  try {
    const raw = await readFile(manifestPath, 'utf-8');
    return JSON.parse(raw) as VaultManifest;
  } catch {
    return {};
  }
}

async function saveManifest(
  vaultDir: string,
  manifest: VaultManifest,
): Promise<void> {
  await mkdir(vaultDir, { recursive: true });
  const manifestPath = join(vaultDir, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf-8');
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export async function vaultCommand(args: string[]): Promise<void> {
  const sub = args[0];

  switch (sub) {
    case 'list':
      return vaultList();
    case 'set':
      return vaultSet(args.slice(1));
    case 'delete':
      return vaultDelete(args.slice(1));
    case '--help':
    case '-h':
    case undefined:
      return vaultHelp();
    default:
      console.error(color.red(`Unknown vault sub-command: ${sub}`));
      vaultHelp();
      process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// vault list
// ---------------------------------------------------------------------------

async function vaultList(): Promise<void> {
  const vaultDir = await getVaultDir();
  const manifest = await loadManifest(vaultDir);
  const keys = Object.keys(manifest);

  console.log(color.bold('Chitin Shell — Vault'));
  console.log();

  if (keys.length === 0) {
    console.log(color.dim('  No vault entries found.'));
    console.log(color.dim('  Use "chitin-shell vault set <key> --type <type> --value <value>" to add one.'));
    return;
  }

  console.log(color.dim(`  ${keys.length} key(s):`));
  console.log();

  for (const key of keys) {
    const entry = manifest[key];
    console.log(
      `  ${color.cyan(key)}  ${color.dim(entry.type)}  ${color.dim(entry.created_at)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// vault set
// ---------------------------------------------------------------------------

const VALID_TYPES = ['api_key', 'bearer', 'oauth', 'basic', 'custom'];

async function vaultSet(args: string[]): Promise<void> {
  const key = args[0];
  if (!key || key.startsWith('--')) {
    console.error(color.red('Usage: chitin-shell vault set <key> --type <type> --value <value>'));
    process.exit(1);
  }

  const type = parseFlag(args, '--type');
  const value = parseFlag(args, '--value');

  if (!type) {
    console.error(color.red(`Missing --type. Valid types: ${VALID_TYPES.join(', ')}`));
    process.exit(1);
  }

  if (!VALID_TYPES.includes(type)) {
    console.error(color.red(`Invalid type "${type}". Valid types: ${VALID_TYPES.join(', ')}`));
    process.exit(1);
  }

  if (!value) {
    console.error(color.red('Missing --value'));
    process.exit(1);
  }

  const vaultDir = await getVaultDir();
  const manifest = await loadManifest(vaultDir);

  const isUpdate = key in manifest;
  manifest[key] = {
    type,
    created_at: new Date().toISOString(),
  };
  await saveManifest(vaultDir, manifest);

  // In a real implementation, the value would be encrypted and stored.
  // For now we only store the manifest (type + timestamp), NOT the actual value.
  // The value is passed to the in-memory vault at runtime.

  if (isUpdate) {
    console.log(color.yellow(`  Updated vault entry: ${key}`));
  } else {
    console.log(color.green(`  Added vault entry: ${key}`));
  }
  console.log(color.dim(`  Type: ${type}`));
}

// ---------------------------------------------------------------------------
// vault delete
// ---------------------------------------------------------------------------

async function vaultDelete(args: string[]): Promise<void> {
  const key = args[0];
  if (!key || key.startsWith('--')) {
    console.error(color.red('Usage: chitin-shell vault delete <key>'));
    process.exit(1);
  }

  const vaultDir = await getVaultDir();
  const manifest = await loadManifest(vaultDir);

  if (!(key in manifest)) {
    console.error(color.red(`  Vault key "${key}" not found.`));
    process.exit(1);
  }

  delete manifest[key];
  await saveManifest(vaultDir, manifest);

  console.log(color.green(`  Deleted vault entry: ${key}`));
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function vaultHelp(): void {
  console.log(color.bold('chitin-shell vault'));
  console.log();
  console.log('  Sub-commands:');
  console.log(`    ${color.cyan('list')}     List all vault keys (values are never shown)`);
  console.log(`    ${color.cyan('set')}      Set a vault entry`);
  console.log(`    ${color.cyan('delete')}   Delete a vault entry`);
  console.log();
  console.log('  Usage:');
  console.log('    chitin-shell vault list');
  console.log('    chitin-shell vault set <key> --type api_key|bearer|oauth|basic|custom --value <value>');
  console.log('    chitin-shell vault delete <key>');
}
