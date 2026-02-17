/**
 * Audit Logger — Type Definitions
 *
 * Every Intent, verification decision, and execution result is logged.
 * Logs are immutable — optionally anchored on-chain for tamper-proof auditability.
 */

import type { SecurityTier } from '../intent/types.js';

/** A single audit log entry */
export interface AuditEntry {
  id: string;
  timestamp: string;
  intent_id: string;
  agent_did: string;
  action_type: string;
  tier: SecurityTier;
  decision: 'approved' | 'rejected';
  reason: string;
  execution_result?: 'success' | 'error';
  execution_error?: string;
  execution_time_ms?: number;
}

/** Audit logger interface */
export interface IAuditLogger {
  log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<AuditEntry>;
  query(filter: AuditQueryFilter): Promise<AuditEntry[]>;
}

/** Filter for querying audit logs */
export interface AuditQueryFilter {
  /** Return the last N entries */
  last?: number;
  /** Filter by agent DID */
  agent_did?: string;
  /** Filter by action type */
  action_type?: string;
  /** Filter by decision */
  decision?: 'approved' | 'rejected';
  /** Filter by date range (ISO string) */
  from?: string;
  /** Filter by date range (ISO string) */
  to?: string;
}
