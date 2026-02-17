/**
 * Anchored Audit Logger — Wraps LocalAuditLogger with automatic on-chain anchoring.
 *
 * Every log entry is stored locally AND accumulated for periodic Merkle root
 * anchoring to the AuditLog smart contract on Base L2.
 *
 * Anchoring is triggered automatically when the pending batch reaches batchSize,
 * or can be triggered manually via forceAnchor().
 */

import type { AuditEntry, IAuditLogger, AuditQueryFilter } from './types.js';
import { LocalAuditLogger } from './local-logger.js';
import {
  AuditAnchor,
  type AnchorConfig,
  type AnchorResult,
  type InclusionProof,
} from './anchor.js';

/**
 * Audit logger that writes locally and automatically anchors batches on-chain.
 *
 * Usage:
 * ```ts
 * const logger = new AnchoredAuditLogger(anchorConfig);
 * await logger.log({ intent_id: '...', ... });
 * // Anchor is triggered automatically at batchSize, or:
 * await logger.forceAnchor();
 * ```
 */
export class AnchoredAuditLogger implements IAuditLogger {
  private localLogger: LocalAuditLogger;
  private auditAnchor: AuditAnchor;
  private batchSize: number;
  private pendingSinceLastAnchor = 0;

  constructor(anchorConfig: AnchorConfig, auditDir?: string) {
    this.localLogger = new LocalAuditLogger(auditDir);
    this.auditAnchor = new AuditAnchor(anchorConfig);
    this.batchSize = anchorConfig.batchSize ?? 100;
  }

  /**
   * Log an entry locally and add it to the pending anchor batch.
   * If the batch reaches batchSize, an anchor is triggered automatically.
   */
  async log(
    entry: Omit<AuditEntry, 'id' | 'timestamp'>,
  ): Promise<AuditEntry> {
    // Write to local JSONL
    const complete = await this.localLogger.log(entry);

    // Add to pending anchor batch
    this.auditAnchor.addEntries([complete]);
    this.pendingSinceLastAnchor++;

    // Auto-anchor at batch size
    if (this.pendingSinceLastAnchor >= this.batchSize) {
      await this.forceAnchor();
    }

    return complete;
  }

  /**
   * Query entries from local storage.
   */
  async query(filter: AuditQueryFilter): Promise<AuditEntry[]> {
    return this.localLogger.query(filter);
  }

  /**
   * Force an anchor of pending entries to the on-chain contract.
   *
   * @returns AnchorResult on success, or null if no pending entries.
   */
  async forceAnchor(): Promise<AnchorResult | null> {
    this.pendingSinceLastAnchor = 0;
    return this.auditAnchor.anchor();
  }

  /** Get all completed anchors */
  getAnchors(): AnchorResult[] {
    return this.auditAnchor.getAnchors();
  }

  /** Get the number of entries pending anchor */
  getPendingCount(): number {
    return this.auditAnchor.getPendingCount();
  }

  /**
   * Generate an inclusion proof for an entry in a specific anchor.
   *
   * @param commitmentId - The anchor commitment ID
   * @param entryIndex - Index of the entry within that anchor's batch
   */
  generateInclusionProof(
    commitmentId: number,
    entryIndex: number,
  ): InclusionProof | null {
    return this.auditAnchor.generateProof(commitmentId, entryIndex);
  }
}
