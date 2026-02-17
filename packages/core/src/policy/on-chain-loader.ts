/**
 * On-Chain Policy Loader
 *
 * Reads policy configuration from an AgentPolicy smart contract via JSON-RPC.
 * Zero external dependencies — uses only Node.js built-in fetch() and manual ABI encoding.
 */

import type { PolicyConfig, TierConfig } from './types.js';

// ---------------------------------------------------------------------------
// Pre-computed function selectors (keccak256 of signature, first 4 bytes)
// ---------------------------------------------------------------------------

const SELECTORS = {
  policyVersion: '0x58355ead', // keccak256("policyVersion()")
  getActionTier: '0x2bd0254b', // keccak256("getActionTier(string)")
  getTierActions: '0x7b2cadae', // keccak256("getTierActions(uint8)")
  verifyAction: '0xc336fd36', // keccak256("verifyAction(string,string,bytes32)")
} as const;

// ---------------------------------------------------------------------------
// ABI subset (informational — encoding is done manually)
// ---------------------------------------------------------------------------

/** ABI subset for the AgentPolicy contract (read-only functions) */
export const AGENT_POLICY_ABI = [
  {
    name: 'policyVersion',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'uint256' }],
  },
  {
    name: 'getActionTier',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'action', type: 'string' }],
    outputs: [{ type: 'uint8' }],
  },
  {
    name: 'getTierActions',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'tier', type: 'uint8' }],
    outputs: [{ type: 'string[]' }],
  },
  {
    name: 'verifyAction',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'agentDid', type: 'string' },
      { name: 'action', type: 'string' },
      { name: 'intentHash', type: 'bytes32' },
    ],
    outputs: [
      { name: 'approved', type: 'bool' },
      { name: 'tier', type: 'uint8' },
      { name: 'reason', type: 'string' },
    ],
  },
] as const;

// ---------------------------------------------------------------------------
// Minimal ABI Encoding Helpers
// ---------------------------------------------------------------------------

/** Encode a uint8 value as a 32-byte ABI word */
export function encodeUint8(value: number): string {
  if (value < 0 || value > 255) throw new Error(`uint8 out of range: ${value}`);
  return value.toString(16).padStart(64, '0');
}

/** Encode a string as ABI-encoded dynamic data (offset + length + padded data) */
export function encodeString(value: string): string {
  const hex = Buffer.from(value, 'utf-8').toString('hex');
  const byteLength = hex.length / 2;
  const lengthHex = byteLength.toString(16).padStart(64, '0');
  // Pad data to 32-byte boundary
  const paddedData = hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');
  return lengthHex + paddedData;
}

/** Encode a bytes32 value (must be a 0x-prefixed 66-char hex string) */
export function encodeBytes32(value: string): string {
  const cleaned = value.startsWith('0x') ? value.slice(2) : value;
  if (cleaned.length !== 64) throw new Error(`bytes32 must be 32 bytes, got ${cleaned.length / 2}`);
  return cleaned;
}

/** Decode a uint256 from a 64-char hex string */
export function decodeUint256(hex: string): bigint {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + cleaned.slice(0, 64));
}

/** Decode a uint8 from a 64-char hex word */
export function decodeUint8(hex: string): number {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  const value = parseInt(cleaned.slice(0, 64), 16);
  if (value > 255) throw new Error(`uint8 out of range: ${value}`);
  return value;
}

/** Decode a bool from a 64-char hex word */
export function decodeBool(hex: string): boolean {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  return parseInt(cleaned.slice(0, 64), 16) !== 0;
}

/** Decode a string from ABI-encoded data at a given byte offset */
export function decodeString(fullHex: string, byteOffset: number): string {
  const cleaned = fullHex.startsWith('0x') ? fullHex.slice(2) : fullHex;
  // The offset points to the start of the string data (length + data)
  const charOffset = byteOffset * 2;
  const length = parseInt(cleaned.slice(charOffset, charOffset + 64), 16);
  const dataStart = charOffset + 64;
  const dataHex = cleaned.slice(dataStart, dataStart + length * 2);
  return Buffer.from(dataHex, 'hex').toString('utf-8');
}

/** Decode a string[] from ABI-encoded data at a given byte offset */
export function decodeStringArray(fullHex: string, byteOffset: number): string[] {
  const cleaned = fullHex.startsWith('0x') ? fullHex.slice(2) : fullHex;
  const charOffset = byteOffset * 2;

  // First word at offset = array length
  const arrayLength = parseInt(cleaned.slice(charOffset, charOffset + 64), 16);
  if (arrayLength === 0) return [];

  const results: string[] = [];

  // Next N words = offsets to each string (relative to array start)
  for (let i = 0; i < arrayLength; i++) {
    const offsetSlotStart = charOffset + 64 + i * 64;
    const stringRelOffset = parseInt(cleaned.slice(offsetSlotStart, offsetSlotStart + 64), 16);
    // String offset is relative to the array data start (charOffset)
    const absoluteByteOffset = byteOffset + 32 + stringRelOffset;
    results.push(decodeString(fullHex, absoluteByteOffset));
  }

  return results;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for on-chain policy loading */
export interface OnChainPolicyConfig {
  /** RPC endpoint URL */
  rpcUrl: string;
  /** AgentPolicy contract address */
  contractAddress: string;
  /** Chain ID */
  chainId: number;
  /** Cache TTL in milliseconds (default: 5 minutes) */
  cacheTtlMs?: number;
}

/** On-chain verification result */
export interface OnChainVerificationResult {
  approved: boolean;
  tier: number;
  reason: string;
  txHash?: string;
}

// ---------------------------------------------------------------------------
// Tier descriptions and verification levels
// ---------------------------------------------------------------------------

const TIER_DESCRIPTIONS: Record<number, { description: string; verification: TierConfig['verification'] }> = {
  0: { description: 'Read-only and internal operations', verification: 'none' },
  1: { description: 'Low-risk write operations to whitelisted targets', verification: 'local' },
  2: { description: 'Higher-risk operations requiring on-chain verification', verification: 'on_chain' },
  3: { description: 'Critical operations requiring human approval', verification: 'human_approval' },
};

// ---------------------------------------------------------------------------
// OnChainPolicyLoader
// ---------------------------------------------------------------------------

/**
 * Loads policy configuration from an on-chain AgentPolicy contract.
 * Uses JSON-RPC `eth_call` directly (no viem/ethers dependency).
 */
export class OnChainPolicyLoader {
  private config: OnChainPolicyConfig;
  private cache: { policy: PolicyConfig; timestamp: number } | null = null;
  private cacheTtlMs: number;

  constructor(config: OnChainPolicyConfig) {
    this.config = config;
    this.cacheTtlMs = config.cacheTtlMs ?? 300_000; // 5 minutes
  }

  /**
   * Load the full policy from the contract.
   * Calls getTierActions(0..3) to reconstruct the full PolicyConfig.
   * Results are cached for `cacheTtlMs` milliseconds.
   */
  async loadPolicy(): Promise<PolicyConfig> {
    // Check cache
    if (this.cache && Date.now() - this.cache.timestamp < this.cacheTtlMs) {
      return this.cache.policy;
    }

    // Get policy version
    const version = await this.getPolicyVersion();

    // Get actions for each tier (0-3)
    const tierActions: string[][] = [];
    for (let tier = 0; tier <= 3; tier++) {
      const calldata = SELECTORS.getTierActions + encodeUint8(tier);
      const result = await this.ethCall(calldata);
      // Result is ABI-encoded string[] — the outer tuple has one element at offset 0x20
      const outerOffset = parseInt(result.slice(2, 66), 16);
      tierActions.push(decodeStringArray(result, outerOffset));
    }

    const policy: PolicyConfig = {
      version: version.toString(),
      tiers: {
        tier_0: {
          description: TIER_DESCRIPTIONS[0].description,
          actions: tierActions[0],
          verification: TIER_DESCRIPTIONS[0].verification,
        },
        tier_1: {
          description: TIER_DESCRIPTIONS[1].description,
          actions: tierActions[1],
          verification: TIER_DESCRIPTIONS[1].verification,
          constraints: {
            recipient_whitelist: true,
            rate_limit: { max: 10, window: '1m' },
          },
        },
        tier_2: {
          description: TIER_DESCRIPTIONS[2].description,
          actions: tierActions[2],
          verification: TIER_DESCRIPTIONS[2].verification,
          constraints: {
            rate_limit: { max: 5, window: '1h' },
          },
        },
        tier_3: {
          description: TIER_DESCRIPTIONS[3].description,
          actions: tierActions[3],
          verification: TIER_DESCRIPTIONS[3].verification,
          multisig: {
            required: 2,
            timeout: '24h',
          },
        },
      },
    };

    this.cache = { policy, timestamp: Date.now() };
    return policy;
  }

  /**
   * Verify an action on-chain (calls verifyAction on the contract).
   * This is used for tier 2+ actions that require on-chain verification.
   */
  async verifyOnChain(
    agentDid: string,
    action: string,
    intentHash: string,
  ): Promise<OnChainVerificationResult> {
    // Build calldata for verifyAction(string,string,bytes32)
    // Dynamic types (string, string) use offsets; bytes32 is static
    const selector = SELECTORS.verifyAction;

    // Layout: selector + offset_agentDid + offset_action + bytes32_intentHash + agentDid_data + action_data
    // Offsets are relative to the start of the params (after selector)
    // 3 slots of head data (offset, offset, bytes32) = 96 bytes = 0x60
    const agentDidEncoded = encodeString(agentDid);
    const actionEncoded = encodeString(action);
    const bytes32Encoded = encodeBytes32(intentHash);

    // Head slot 0: offset to agentDid (3 * 32 = 96 = 0x60)
    const agentDidOffset = (96).toString(16).padStart(64, '0');
    // Head slot 1: offset to action (96 + 32 + agentDid padded data length)
    const agentDidTotalBytes = 32 + (agentDidEncoded.length - 64) / 2 + 32; // length word + data
    const actionOffset = (96 + agentDidEncoded.length / 2).toString(16).padStart(64, '0');

    const calldata =
      selector + agentDidOffset + actionOffset + bytes32Encoded + agentDidEncoded + actionEncoded;

    const result = await this.ethCall(calldata);
    const cleaned = result.startsWith('0x') ? result.slice(2) : result;

    // Decode: bool approved (slot 0), uint8 tier (slot 1), string reason (slot 2 = offset)
    const approved = decodeBool(cleaned.slice(0, 64));
    const tier = decodeUint8(cleaned.slice(64, 128));
    const reasonOffset = parseInt(cleaned.slice(128, 192), 16);
    const reason = decodeString(cleaned, reasonOffset);

    return { approved, tier, reason };
  }

  /**
   * Get the current policy version from the contract.
   */
  async getPolicyVersion(): Promise<number> {
    const calldata = SELECTORS.policyVersion;
    const result = await this.ethCall(calldata);
    return Number(decodeUint256(result));
  }

  /**
   * Clear the in-memory cache, forcing the next loadPolicy() to fetch fresh data.
   */
  clearCache(): void {
    this.cache = null;
  }

  /**
   * Make an eth_call JSON-RPC request.
   */
  private async ethCall(data: string): Promise<string> {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_call',
      params: [
        {
          to: this.config.contractAddress,
          data: data.startsWith('0x') ? data : '0x' + data,
        },
        'latest',
      ],
    });

    const response = await fetch(this.config.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    if (!response.ok) {
      throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    }

    const json = (await response.json()) as { result?: string; error?: { message: string; code: number } };

    if (json.error) {
      throw new Error(`RPC error: ${json.error.message} (code: ${json.error.code})`);
    }

    if (!json.result) {
      throw new Error('RPC response missing result');
    }

    return json.result;
  }
}
