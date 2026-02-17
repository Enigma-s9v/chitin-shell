/**
 * ERC-8004 DID Resolver
 *
 * Resolves and verifies agent identity against the ERC-8004 IdentityRegistry.
 * DID format: did:chitin:<chainId>:<registryAddress>:<agentId>
 *
 * Zero external dependencies — uses only Node.js built-in fetch() and manual ABI encoding.
 */

// ---------------------------------------------------------------------------
// Pre-computed function selectors
// ---------------------------------------------------------------------------

const SELECTORS = {
  ownerOf: '0x6352211e',    // keccak256("ownerOf(uint256)")
  agentURI: '0x78396cb3',   // keccak256("agentURI(uint256)")
  totalSupply: '0x18160ddd', // keccak256("totalSupply()")
} as const;

// ---------------------------------------------------------------------------
// Minimal ABI Encoding/Decoding Helpers
// ---------------------------------------------------------------------------

/** Encode a uint256 value as a 32-byte ABI word */
function encodeUint256(value: number | bigint): string {
  const hex = BigInt(value).toString(16);
  return hex.padStart(64, '0');
}

/** Decode an address from a 64-char hex word (last 20 bytes) */
function decodeAddress(hex: string): string {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  // Address is in the last 40 chars of the 64-char word
  return '0x' + cleaned.slice(24, 64).toLowerCase();
}

/** Decode a uint256 from a 64-char hex word */
function decodeUint256(hex: string): bigint {
  const cleaned = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + cleaned.slice(0, 64));
}

/** Decode a string from ABI-encoded data at a given byte offset */
function decodeString(fullHex: string, byteOffset: number): string {
  const cleaned = fullHex.startsWith('0x') ? fullHex.slice(2) : fullHex;
  const charOffset = byteOffset * 2;
  const length = parseInt(cleaned.slice(charOffset, charOffset + 64), 16);
  const dataStart = charOffset + 64;
  const dataHex = cleaned.slice(dataStart, dataStart + length * 2);
  return Buffer.from(dataHex, 'hex').toString('utf-8');
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Configuration for the DID resolver */
export interface DidResolverConfig {
  /** RPC endpoint URL */
  rpcUrl: string;
  /** ERC-8004 IdentityRegistry contract address */
  registryAddress: string;
  /** Chain ID */
  chainId: number;
}

/** Result of resolving a DID */
export interface ResolvedDid {
  /** The agent DID (did:chitin:...) */
  did: string;
  /** The ERC-8004 agent ID (token ID) */
  agentId?: number;
  /** Owner address */
  ownerAddress?: string;
  /** Agent URI from ERC-8004 */
  agentUri?: string;
  /** Whether the DID is verified on-chain */
  verified: boolean;
}

/** Parsed components of a did:chitin: DID */
export interface ParsedDid {
  chainId: number;
  registryAddress: string;
  agentId: number;
}

// ---------------------------------------------------------------------------
// DID Format
// ---------------------------------------------------------------------------

const DID_PREFIX = 'did:chitin:';
const DID_REGEX = /^did:chitin:(\d+):(0x[0-9a-fA-F]{40}):(\d+)$/;

// ---------------------------------------------------------------------------
// DidResolver
// ---------------------------------------------------------------------------

/**
 * Resolves agent identity against the ERC-8004 IdentityRegistry.
 *
 * DID format: did:chitin:<chainId>:<registryAddress>:<agentId>
 * Example: did:chitin:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42
 */
export class DidResolver {
  private config: DidResolverConfig;

  constructor(config: DidResolverConfig) {
    this.config = config;
  }

  /**
   * Resolve a DID to its on-chain identity.
   * Returns verified: false if the DID format is invalid or the on-chain lookup fails.
   */
  async resolve(did: string): Promise<ResolvedDid> {
    const parsed = DidResolver.parseDid(did);
    if (!parsed) {
      return { did, verified: false };
    }

    // Verify chain ID matches our config
    if (parsed.chainId !== this.config.chainId) {
      return { did, agentId: parsed.agentId, verified: false };
    }

    // Verify registry address matches
    if (parsed.registryAddress.toLowerCase() !== this.config.registryAddress.toLowerCase()) {
      return { did, agentId: parsed.agentId, verified: false };
    }

    try {
      // Call ownerOf(agentId)
      const ownerCalldata = SELECTORS.ownerOf + encodeUint256(parsed.agentId);
      const ownerResult = await this.ethCall(ownerCalldata);
      const ownerAddress = decodeAddress(ownerResult);

      // Call agentURI(agentId)
      let agentUri: string | undefined;
      try {
        const uriCalldata = SELECTORS.agentURI + encodeUint256(parsed.agentId);
        const uriResult = await this.ethCall(uriCalldata);
        // agentURI returns a string — offset in first word, then string data
        const cleaned = uriResult.startsWith('0x') ? uriResult.slice(2) : uriResult;
        const offset = parseInt(cleaned.slice(0, 64), 16);
        agentUri = decodeString(uriResult, offset);
      } catch {
        // agentURI might not be set — that's OK
      }

      return {
        did,
        agentId: parsed.agentId,
        ownerAddress,
        agentUri,
        verified: true,
      };
    } catch {
      // ownerOf reverts for non-existent tokens
      return {
        did,
        agentId: parsed.agentId,
        verified: false,
      };
    }
  }

  /**
   * Verify that a DID matches an on-chain ERC-8004 identity.
   * Optionally checks that the owner matches an expected address.
   */
  async verify(did: string, expectedOwner?: string): Promise<boolean> {
    const resolved = await this.resolve(did);
    if (!resolved.verified) return false;

    if (expectedOwner) {
      return resolved.ownerAddress?.toLowerCase() === expectedOwner.toLowerCase();
    }

    return true;
  }

  /**
   * Create a did:chitin: DID from an ERC-8004 agent ID.
   */
  static fromAgentId(chainId: number, registryAddress: string, agentId: number): string {
    return `${DID_PREFIX}${chainId}:${registryAddress}:${agentId}`;
  }

  /**
   * Parse a did:chitin: DID into its component parts.
   * Returns null if the DID format is invalid.
   */
  static parseDid(did: string): ParsedDid | null {
    if (!did || typeof did !== 'string') return null;

    const match = did.match(DID_REGEX);
    if (!match) return null;

    const chainId = parseInt(match[1], 10);
    const registryAddress = match[2];
    const agentId = parseInt(match[3], 10);

    if (isNaN(chainId) || isNaN(agentId)) return null;
    if (chainId <= 0 || agentId < 0) return null;

    return { chainId, registryAddress, agentId };
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
          to: this.config.registryAddress,
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
