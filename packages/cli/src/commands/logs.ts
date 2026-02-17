/**
 * `chitin-shell logs` — Display audit log entries
 *
 * Reads from the local audit logger and displays entries in a table format.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AuditEntry } from '@chitin-id/shell-core';
import { color, tierLabel, padRight, truncate, parseFlag, loadConfig } from '../utils.js';

export async function logsCommand(args: string[]): Promise<void> {
  // Parse filters
  const last = parseFlag(args, '--last');
  const actionFilter = parseFlag(args, '--action');
  const decisionFilter = parseFlag(args, '--decision') as
    | 'approved'
    | 'rejected'
    | undefined;
  const agentFilter = parseFlag(args, '--agent');

  // Load audit log file
  let auditDir: string;
  try {
    const config = await loadConfig();
    auditDir = join(process.cwd(), config.auditDir);
  } catch {
    auditDir = join(process.cwd(), '.chitin-shell/audit');
  }

  const auditFile = join(auditDir, 'audit.jsonl');

  let raw: string;
  try {
    raw = await readFile(auditFile, 'utf-8');
  } catch {
    console.log(color.dim('  No audit logs found.'));
    console.log(color.dim(`  Expected at: ${auditFile}`));
    return;
  }

  // Parse JSONL
  let entries: AuditEntry[] = raw
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      try {
        return JSON.parse(line) as AuditEntry;
      } catch {
        return null;
      }
    })
    .filter((entry): entry is AuditEntry => entry !== null);

  // Apply filters
  if (agentFilter) {
    entries = entries.filter((e) => e.agent_did.includes(agentFilter));
  }
  if (actionFilter) {
    entries = entries.filter((e) => e.action_type === actionFilter);
  }
  if (decisionFilter) {
    entries = entries.filter((e) => e.decision === decisionFilter);
  }
  if (last) {
    const n = parseInt(last, 10);
    if (!isNaN(n) && n > 0) {
      entries = entries.slice(-n);
    }
  }

  if (entries.length === 0) {
    console.log(color.dim('  No matching audit entries found.'));
    return;
  }

  // Display header
  console.log(color.bold('Chitin Shell — Audit Log'));
  console.log(color.dim(`  Showing ${entries.length} entries`));
  console.log();

  // Table header
  const header =
    `  ${padRight('TIMESTAMP', 24)} ` +
    `${padRight('TIER', 8)} ` +
    `${padRight('DECISION', 12)} ` +
    `${padRight('ACTION', 18)} ` +
    `REASON`;
  console.log(color.dim(header));
  console.log(color.dim('  ' + '-'.repeat(90)));

  // Table rows
  for (const entry of entries) {
    const ts = entry.timestamp.replace('T', ' ').slice(0, 19);
    const tier = tierLabel(entry.tier);
    const decision =
      entry.decision === 'approved'
        ? color.green(padRight('approved', 12))
        : color.red(padRight('rejected', 12));
    const action = padRight(entry.action_type, 18);
    const reason = truncate(entry.reason, 40);

    console.log(`  ${padRight(ts, 24)} ${padRight(tier, 19)} ${decision} ${action} ${color.dim(reason)}`);

    // Show execution result if present
    if (entry.execution_result) {
      const execStatus =
        entry.execution_result === 'success'
          ? color.green('success')
          : color.red(`error: ${entry.execution_error ?? 'unknown'}`);
      const time = entry.execution_time_ms ? ` (${entry.execution_time_ms}ms)` : '';
      console.log(color.dim(`  ${''.padStart(24)} ${''.padStart(8)} execution: ${execStatus}${time}`));
    }
  }
}
