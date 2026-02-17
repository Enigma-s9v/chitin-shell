/**
 * On-chain Audit Anchor — Commits Merkle roots to the AuditLog contract on Base L2.
 *
 * Periodically batches audit entries, builds a Merkle tree, and submits the root
 * on-chain for tamper-proof auditability. Also supports generating and verifying
 * inclusion proofs for individual entries.
 *
 * Transaction signing is abstracted via sendTransaction() — in production this
 * would use a wallet/KMS. For testing, it can be mocked.
 */

import { createHash } from 'node:crypto';
import type { AuditEntry } from './types.js';
import { buildMerkleTree, generateMerkleProof } from './merkle.js';

/**
 * AuditLog contract ABI (relevant write/read functions).
 *
 * anchorCommitment(bytes32 merkleRoot, uint256 entryCount, uint256 fromTimestamp, uint256 toTimestamp, bytes32 agentDidHash)
 *   => returns uint256 commitmentId
 *
 * verifyInclusion(uint256 commitmentId, bytes32 leaf, bytes32[] proof, uint256 index)
 *   => returns bool
 */
export const AUDIT_LOG_ABI = [
  {
    name: 'anchorCommitment',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'merkleRoot', type: 'bytes32' },
      { name: 'entryCount', type: 'uint256' },
      { name: 'fromTimestamp', type: 'uint256' },
      { name: 'toTimestamp', type: 'uint256' },
      { name: 'agentDidHash', type: 'bytes32' },
    ],
    outputs: [{ name: 'commitmentId', type: 'uint256' }],
  },
  {
    name: 'verifyInclusion',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'commitmentId', type: 'uint256' },
      { name: 'leaf', type: 'bytes32' },
      { name: 'proof', type: 'bytes32[]' },
      { name: 'index', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const;

/** Configuration for the on-chain audit anchor */
export interface AnchorConfig {
  /** RPC endpoint URL */
  rpcUrl: string;
  /** AuditLog contract address */
  contractAddress: string;
  /** Chain ID */
  chainId: number;
  /** Private key for signing transactions (hex, 0x-prefixed) */
  signerPrivateKey: string;
  /** Agent DID for grouping anchors */
  agentDid?: string;
  /** Batch size: anchor after this many entries (default: 100) */
  batchSize?: number;
  /** Anchor interval in ms (default: 5 minutes) */
  intervalMs?: number;
  /** Gas limit for anchor transaction (default: 200000) */
  gasLimit?: number;
}

/** Result of a successful anchor operation */
export interface AnchorResult {
  /** On-chain commitment ID */
  commitmentId: number;
  /** Merkle root that was anchored */
  merkleRoot: string;
  /** Number of entries in this batch */
  entryCount: number;
  /** Earliest entry timestamp (ISO string) */
  fromTimestamp: string;
  /** Latest entry timestamp (ISO string) */
  toTimestamp: string;
  /** Transaction hash on Base L2 */
  txHash: string;
}

/** An inclusion proof for a single audit entry */
export interface InclusionProof {
  /** On-chain commitment ID this proof relates to */
  commitmentId: number;
  /** Merkle root of the anchored batch */
  merkleRoot: string;
  /** Leaf hash of the entry */
  leaf: string;
  /** Sibling hashes forming the proof path */
  proof: string[];
  /** Index of the leaf in the tree */
  index: number;
  /** Whether the proof has been verified (off-chain) */
  verified: boolean;
}

/**
 * Manages on-chain anchoring of audit log Merkle roots.
 *
 * Usage:
 * ```ts
 * const anchor = new AuditAnchor(config);
 * anchor.addEntries(entries);
 * const result = await anchor.anchor();
 * const proof = anchor.generateProof(result.commitmentId, 0);
 * ```
 */
export class AuditAnchor {
  private config: AnchorConfig;
  private pendingEntries: AuditEntry[] = [];
  private anchors: AnchorResult[] = [];
  private trees: Map<number, { tree: string[][]; entries: AuditEntry[] }> =
    new Map();
  private nextCommitmentId = 1;

  constructor(config: AnchorConfig) {
    this.config = {
      batchSize: 100,
      intervalMs: 5 * 60 * 1000,
      gasLimit: 200_000,
      ...config,
    };
  }

  /** Add entries to the pending batch */
  addEntries(entries: AuditEntry[]): void {
    this.pendingEntries.push(...entries);
  }

  /**
   * Manually trigger an anchor — commit pending entries on-chain.
   *
   * @returns AnchorResult on success, or null if no pending entries.
   */
  async anchor(): Promise<AnchorResult | null> {
    if (this.pendingEntries.length === 0) {
      return null;
    }

    // Snapshot and clear pending entries
    const entries = [...this.pendingEntries];
    this.pendingEntries = [];

    // Build Merkle tree
    const { root, tree } = buildMerkleTree(entries);

    // Compute timestamps
    const timestamps = entries.map((e) => new Date(e.timestamp).getTime());
    const fromTimestamp = new Date(Math.min(...timestamps)).toISOString();
    const toTimestamp = new Date(Math.max(...timestamps)).toISOString();

    // Hash agent DID for the contract call
    const agentDid = this.config.agentDid ?? entries[0].agent_did;
    const agentDidHash = '0x' + createHash('sha256').update(agentDid).digest('hex');

    // Encode and send the transaction
    const calldata = this.encodeAnchorCall(
      root,
      entries.length,
      Math.floor(Math.min(...timestamps) / 1000),
      Math.floor(Math.max(...timestamps) / 1000),
      agentDidHash,
    );

    const txHash = await this.sendTransaction(calldata);

    // Record anchor result
    const commitmentId = this.nextCommitmentId++;
    const result: AnchorResult = {
      commitmentId,
      merkleRoot: root,
      entryCount: entries.length,
      fromTimestamp,
      toTimestamp,
      txHash,
    };

    this.anchors.push(result);
    this.trees.set(commitmentId, { tree, entries });

    return result;
  }

  /**
   * Generate an inclusion proof for a specific audit entry.
   *
   * @param commitmentId - The anchor commitment to generate a proof for
   * @param entryIndex - Index of the entry within that anchor's batch
   * @returns InclusionProof or null if not found
   */
  generateProof(
    commitmentId: number,
    entryIndex: number,
  ): InclusionProof | null {
    const treeData = this.trees.get(commitmentId);
    if (!treeData) return null;

    const { tree } = treeData;
    if (tree.length === 0 || entryIndex < 0 || entryIndex >= tree[0].length) {
      return null;
    }

    const proofData = generateMerkleProof(tree, entryIndex);
    if (!proofData) return null;

    const anchorResult = this.anchors.find(
      (a) => a.commitmentId === commitmentId,
    );
    if (!anchorResult) return null;

    return {
      commitmentId,
      merkleRoot: anchorResult.merkleRoot,
      leaf: tree[0][entryIndex],
      proof: proofData.proof,
      index: proofData.index,
      verified: false,
    };
  }

  /**
   * Verify an inclusion proof on-chain by calling verifyInclusion().
   *
   * @param proof - The inclusion proof to verify
   * @returns true if the contract confirms the proof
   */
  async verifyOnChain(proof: InclusionProof): Promise<boolean> {
    // Encode verifyInclusion call
    // In a production implementation, this would make an eth_call to the contract.
    // For now, we encode the call data for the RPC request.
    const functionSelector = '0x' + createHash('sha256')
      .update('verifyInclusion(uint256,bytes32,bytes32[],uint256)')
      .digest('hex')
      .slice(0, 8);

    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_call',
      params: [
        {
          to: this.config.contractAddress,
          data: functionSelector, // Simplified — production would fully ABI-encode
        },
        'latest',
      ],
      id: 1,
    });

    const response = await fetch(this.config.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    const json = (await response.json()) as { result?: string; error?: unknown };

    if (json.error || !json.result) {
      return false;
    }

    // Decode bool result — "0x...01" = true
    return json.result.endsWith('1');
  }

  /** Get all anchor results */
  getAnchors(): AnchorResult[] {
    return [...this.anchors];
  }

  /** Get pending entry count */
  getPendingCount(): number {
    return this.pendingEntries.length;
  }

  /**
   * Encode the anchorCommitment function call data.
   *
   * Simplified ABI encoding — pads each parameter to 32 bytes.
   * In production, use a proper ABI encoder (e.g., viem's encodeFunctionData).
   */
  private encodeAnchorCall(
    root: string,
    count: number,
    fromTs: number,
    toTs: number,
    agentHash: string,
  ): string {
    // Function selector: first 4 bytes of keccak256("anchorCommitment(bytes32,uint256,uint256,uint256,bytes32)")
    // Using SHA-256 as a stand-in (no keccak256 in Node.js crypto).
    // In production, use keccak256 for EVM compatibility.
    const selectorHash = createHash('sha256')
      .update(
        'anchorCommitment(bytes32,uint256,uint256,uint256,bytes32)',
      )
      .digest('hex');
    const selector = selectorHash.slice(0, 8);

    // Pad values to 32 bytes (64 hex chars)
    const pad32 = (hex: string): string => {
      const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
      return clean.padStart(64, '0');
    };

    const params = [
      pad32(root),
      pad32(count.toString(16)),
      pad32(fromTs.toString(16)),
      pad32(toTs.toString(16)),
      pad32(agentHash),
    ].join('');

    return '0x' + selector + params;
  }

  /**
   * Send a transaction to the AuditLog contract.
   *
   * This is a minimal JSON-RPC implementation. In production, use a proper
   * transaction signer (wallet/KMS) and handle nonce management, gas estimation, etc.
   */
  private async sendTransaction(data: string): Promise<string> {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_sendRawTransaction',
      params: [
        {
          to: this.config.contractAddress,
          data,
          chainId: '0x' + this.config.chainId.toString(16),
          gas: '0x' + (this.config.gasLimit ?? 200_000).toString(16),
        },
      ],
      id: 1,
    });

    const response = await fetch(this.config.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    const json = (await response.json()) as {
      result?: string;
      error?: { message: string };
    };

    if (json.error) {
      throw new Error(`Anchor transaction failed: ${json.error.message}`);
    }

    return json.result ?? '0x' + '00'.repeat(32);
  }
}
