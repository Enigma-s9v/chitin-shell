/**
 * @chitin-id/shell-cli — Main Entry Point
 *
 * CLI tool for managing Chitin Shell policies, vault, and audit logs.
 * Zero external dependencies — manual arg parsing, ANSI colors, Node.js built-ins only.
 */

import { initCommand } from './commands/init.js';
import { policyCommand } from './commands/policy.js';
import { logsCommand } from './commands/logs.js';
import { vaultCommand } from './commands/vault.js';
import { color } from './utils.js';

const VERSION = '0.1.0-alpha.0';

export async function run(args: string[]): Promise<void> {
  const command = args[0];

  switch (command) {
    case 'init':
      return initCommand(args.slice(1));
    case 'policy':
      return policyCommand(args.slice(1));
    case 'logs':
      return logsCommand(args.slice(1));
    case 'vault':
      return vaultCommand(args.slice(1));
    case '--help':
    case '-h':
    case undefined:
      return showHelp();
    case '--version':
    case '-v':
      return showVersion();
    default:
      console.error(color.red(`Unknown command: ${command}`));
      showHelp();
      process.exit(1);
  }
}

function showHelp(): void {
  console.log(color.bold('chitin-shell') + color.dim(` v${VERSION}`));
  console.log();
  console.log('  The security layer for AI agents — manage policies, vault, and audit logs.');
  console.log();
  console.log(color.bold('  Commands:'));
  console.log(`    ${color.cyan('init')}            Initialize a new Chitin Shell project`);
  console.log(`    ${color.cyan('policy show')}     Display the current policy`);
  console.log(`    ${color.cyan('policy verify')}   Validate a policy file`);
  console.log(`    ${color.cyan('policy test')}     Test an action against the policy`);
  console.log(`    ${color.cyan('logs')}            Show audit log entries`);
  console.log(`    ${color.cyan('vault list')}      List vault keys`);
  console.log(`    ${color.cyan('vault set')}       Set a vault entry`);
  console.log(`    ${color.cyan('vault delete')}    Delete a vault entry`);
  console.log();
  console.log(color.bold('  Options:'));
  console.log('    -h, --help      Show this help message');
  console.log('    -v, --version   Show version');
  console.log();
  console.log(color.dim('  https://chitin.id/shell'));
}

function showVersion(): void {
  console.log(VERSION);
}

// Re-export for programmatic use
export { initCommand } from './commands/init.js';
export { policyCommand } from './commands/policy.js';
export { logsCommand } from './commands/logs.js';
export { vaultCommand } from './commands/vault.js';
