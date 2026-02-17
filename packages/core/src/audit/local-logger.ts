import crypto from 'node:crypto';
import { mkdir, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { IAuditLogger, AuditEntry, AuditQueryFilter } from './types.js';

export class LocalAuditLogger implements IAuditLogger {
  private entries: AuditEntry[] = [];
  private logDir: string;
  private dirEnsured = false;

  constructor(logDir = './.chitin-shell/audit') {
    this.logDir = logDir;
  }

  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<AuditEntry> {
    const complete: AuditEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      ...entry,
    };

    this.entries.push(complete);

    if (!this.dirEnsured) {
      await mkdir(this.logDir, { recursive: true });
      this.dirEnsured = true;
    }

    const filePath = join(this.logDir, 'audit.jsonl');
    await appendFile(filePath, JSON.stringify(complete) + '\n', 'utf-8');

    return complete;
  }

  async query(filter: AuditQueryFilter): Promise<AuditEntry[]> {
    let results = this.entries;

    if (filter.agent_did !== undefined) {
      results = results.filter((e) => e.agent_did === filter.agent_did);
    }

    if (filter.action_type !== undefined) {
      results = results.filter((e) => e.action_type === filter.action_type);
    }

    if (filter.decision !== undefined) {
      results = results.filter((e) => e.decision === filter.decision);
    }

    if (filter.from !== undefined) {
      results = results.filter((e) => e.timestamp >= filter.from!);
    }

    if (filter.to !== undefined) {
      results = results.filter((e) => e.timestamp <= filter.to!);
    }

    if (filter.last !== undefined) {
      results = results.slice(-filter.last);
    }

    return results;
  }
}
