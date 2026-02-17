/**
 * `chitin-shell init` — Initialize a new Chitin Shell project
 *
 * Creates chitin.config.json and chitin-policy.json in the current directory.
 * Does NOT overwrite existing files.
 */

import { writeFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { loadDefaultPolicy } from '@chitin-id/shell-core';
import { color, getConfigFilename, getDefaultPolicyFilename } from '../utils.js';

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function initCommand(args: string[]): Promise<void> {
  const cwd = process.cwd();
  const configFilename = getConfigFilename();
  const policyFilename = getDefaultPolicyFilename();
  const configPath = join(cwd, configFilename);
  const policyPath = join(cwd, policyFilename);

  console.log(color.bold('Chitin Shell — Project Initialization'));
  console.log();

  let createdFiles = 0;

  // Create chitin.config.json
  if (await fileExists(configPath)) {
    console.log(color.yellow(`  ! ${configFilename} already exists — skipping`));
  } else {
    const config = {
      policy: policyFilename,
      auditDir: '.chitin-shell/audit',
    };
    await writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
    console.log(color.green(`  + Created ${configFilename}`));
    createdFiles++;
  }

  // Create chitin-policy.json
  if (await fileExists(policyPath)) {
    console.log(color.yellow(`  ! ${policyFilename} already exists — skipping`));
  } else {
    const policy = loadDefaultPolicy();
    await writeFile(policyPath, JSON.stringify(policy, null, 2) + '\n', 'utf-8');
    console.log(color.green(`  + Created ${policyFilename}`));
    createdFiles++;
  }

  console.log();

  if (createdFiles === 0) {
    console.log(color.dim('  No files created — project already initialized.'));
  } else {
    console.log(color.bold('  Getting started:'));
    console.log();
    console.log(`  1. Edit ${color.cyan(policyFilename)} to customize your security policy`);
    console.log(`  2. Add contacts to ${color.cyan('whitelists.contacts')} for Tier 1 actions`);
    console.log(`  3. Use ${color.cyan('chitin-shell policy verify')} to validate your policy`);
    console.log(`  4. Use ${color.cyan('chitin-shell policy test <action>')} to simulate actions`);
    console.log();
    console.log(color.dim('  Audit logs will be stored in .chitin-shell/audit/'));
  }
}
