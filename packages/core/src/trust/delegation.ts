/**
 * Trust Delegation — DelegationManager
 *
 * Creates, verifies, and manages delegation tokens that allow agents to
 * delegate a subset of their permissions to other agents. Supports
 * multi-level delegation chains with scope narrowing.
 */

import crypto from 'node:crypto';
import type { AgentKeyPair, ActionType } from '../intent/types.js';
import type {
  DelegationScope,
  DelegationToken,
  DelegationResult,
  ITrustStore,
  TrustChain,
} from './types.js';
import { MemoryTrustStore } from './store.js';
import { intersectScopes, scopeAllowsAction, isSubScope, validateScope } from './scope.js';

// Ed25519 DER encoding prefixes (same as intent/signer.ts)
const SPKI_ED25519_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const PKCS8_ED25519_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
  0x20,
]);

/** Parameters for creating a new delegation */
export interface CreateDelegationParams {
  delegatorDid: string;
  delegateDid: string;
  scope: DelegationScope;
  /** Expiry in seconds from now */
  expiresIn: number;
  /** Delegator's key pair for signing */
  keyPair: AgentKeyPair;
  /** For sub-delegation: the parent token's ID */
  parentTokenId?: string;
}

export class DelegationManager {
  private store: ITrustStore;

  constructor(store?: ITrustStore) {
    this.store = store ?? new MemoryTrustStore();
  }

  /**
   * Create a new delegation token, sign it with the delegator's key,
   * and persist it in the trust store.
   */
  async createDelegation(params: CreateDelegationParams): Promise<DelegationToken> {
    const { delegatorDid, delegateDid, scope, expiresIn, keyPair, parentTokenId } = params;

    // Validate scope
    const scopeValidation = validateScope(scope);
    if (!scopeValidation.valid) {
      throw new Error(`Invalid scope: ${scopeValidation.errors.join(', ')}`);
    }

    // If sub-delegation, verify parent exists and allows it
    if (parentTokenId) {
      const parentEntry = await this.store.get(parentTokenId);
      if (!parentEntry) {
        throw new Error(`Parent token ${parentTokenId} not found`);
      }
      if (parentEntry.revoked) {
        throw new Error(`Parent token ${parentTokenId} is revoked`);
      }
      if (parentEntry.token.scope.maxDepth <= 0) {
        throw new Error('Parent token does not allow sub-delegation (maxDepth = 0)');
      }
      if (!isSubScope(parentEntry.token.scope, scope)) {
        throw new Error('Sub-delegation scope exceeds parent scope');
      }
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiresIn * 1000);

    const token: DelegationToken = {
      id: crypto.randomUUID(),
      version: 1,
      delegator: delegatorDid,
      delegate: delegateDid,
      scope,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      ...(parentTokenId ? { parentTokenId } : {}),
      signature: '', // placeholder, signed below
    };

    // Sign the token
    token.signature = signToken(token, keyPair.privateKey);

    // Persist
    await this.store.store(token);

    return token;
  }

  /**
   * Verify a single delegation token against the delegator's public key.
   */
  async verifyDelegation(
    token: DelegationToken,
    delegatorPublicKey: string,
  ): Promise<DelegationResult> {
    // Check expiry
    if (new Date(token.expiresAt) <= new Date()) {
      return { valid: false, reason: 'Token has expired' };
    }

    // Check revocation
    if (await this.store.isRevoked(token.id)) {
      return { valid: false, reason: 'Token has been revoked' };
    }

    // Verify signature
    const publicKeyBytes = Buffer.from(delegatorPublicKey, 'hex');
    if (!verifyTokenSignature(token, publicKeyBytes)) {
      return { valid: false, reason: 'Invalid signature' };
    }

    return {
      valid: true,
      reason: 'Valid delegation',
      effectiveScope: token.scope,
    };
  }

  /**
   * Verify an entire trust chain (ordered root -> leaf).
   * Each token's delegate must be the next token's delegator.
   * Scopes narrow at each level.
   */
  async verifyChain(
    tokens: DelegationToken[],
    publicKeys: Map<string, string>,
  ): Promise<DelegationResult> {
    if (tokens.length === 0) {
      return { valid: false, reason: 'Empty chain' };
    }

    let effectiveScope: DelegationScope = tokens[0].scope;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];

      // Get public key for delegator
      const pubKey = publicKeys.get(token.delegator);
      if (!pubKey) {
        return { valid: false, reason: `No public key for delegator ${token.delegator}` };
      }

      // Verify individual token
      const result = await this.verifyDelegation(token, pubKey);
      if (!result.valid) {
        return { valid: false, reason: `Token ${i} invalid: ${result.reason}` };
      }

      // Check chain continuity: previous delegate == current delegator
      if (i > 0) {
        const prevToken = tokens[i - 1];
        if (prevToken.delegate !== token.delegator) {
          return {
            valid: false,
            reason: `Chain gap at position ${i}: ${prevToken.delegate} != ${token.delegator}`,
          };
        }

        // Check that parent token allows sub-delegation
        if (prevToken.scope.maxDepth <= 0) {
          return {
            valid: false,
            reason: `Depth limit exceeded at position ${i}: parent maxDepth is 0`,
          };
        }
      }

      // Narrow scope through intersection
      if (i > 0) {
        const narrowed = intersectScopes(effectiveScope, token.scope);
        if (!narrowed) {
          return {
            valid: false,
            reason: `Scope exceeds parent at position ${i}`,
          };
        }
        effectiveScope = narrowed;
      }
    }

    const chain: TrustChain = {
      tokens,
      rootAgent: tokens[0].delegator,
      leafAgent: tokens[tokens.length - 1].delegate,
      effectiveScope,
    };

    return {
      valid: true,
      reason: 'Valid trust chain',
      chain,
      effectiveScope,
    };
  }

  /**
   * Revoke a delegation token. Also revokes any sub-delegations
   * that reference this token as their parent.
   */
  async revokeDelegation(tokenId: string): Promise<void> {
    await this.store.revoke(tokenId);

    // Revoke sub-delegations: find all tokens whose parentTokenId == tokenId
    const entry = await this.store.get(tokenId);
    if (entry) {
      const subDelegations = await this.store.getByDelegator(entry.token.delegate);
      for (const sub of subDelegations) {
        if (sub.token.parentTokenId === tokenId && !sub.revoked) {
          await this.revokeDelegation(sub.token.id);
        }
      }
    }
  }

  /**
   * Check if a specific agent has delegated authority for a given action.
   * Searches all active (non-expired, non-revoked) delegations to the agent.
   */
  async checkAuthority(
    agentDid: string,
    action: ActionType,
    target?: string,
  ): Promise<DelegationResult> {
    const entries = await this.store.getByDelegate(agentDid);
    const now = new Date();

    for (const entry of entries) {
      // Skip revoked
      if (entry.revoked) continue;

      // Skip expired
      if (new Date(entry.token.expiresAt) <= now) continue;

      // Check if scope allows this action
      if (scopeAllowsAction(entry.token.scope, action, target)) {
        return {
          valid: true,
          reason: 'Delegated authority found',
          effectiveScope: entry.token.scope,
        };
      }
    }

    return { valid: false, reason: 'No valid delegation found for this action' };
  }

  /**
   * Get all active delegations for an agent (as delegate).
   * "Active" means not expired and not revoked.
   */
  async getActiveDelegations(agentDid: string): Promise<DelegationToken[]> {
    const entries = await this.store.getByDelegate(agentDid);
    const now = new Date();

    return entries
      .filter((e) => !e.revoked && new Date(e.token.expiresAt) > now)
      .map((e) => e.token);
  }
}

// ---------------------------------------------------------------------------
// Signing Helpers (compatible with intent/signer.ts Ed25519 format)
// ---------------------------------------------------------------------------

/**
 * Create the signing payload for a delegation token.
 * SHA-256 hash of the canonicalized token fields (excluding signature).
 */
function createSigningPayload(token: DelegationToken): Buffer {
  const obj: Record<string, unknown> = {
    id: token.id,
    version: token.version,
    delegator: token.delegator,
    delegate: token.delegate,
    scope: token.scope,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
  };
  if (token.parentTokenId !== undefined) {
    obj.parentTokenId = token.parentTokenId;
  }
  const canonical = JSON.stringify(sortKeys(obj));
  const hash = crypto.createHash('sha256').update(canonical).digest();
  return hash;
}

/** Sign a delegation token with an Ed25519 private key (raw 32 bytes) */
function signToken(token: DelegationToken, privateKey: Uint8Array): string {
  const payload = createSigningPayload(token);
  const key = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, privateKey]),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = crypto.sign(null, payload, key);
  return sig.toString('hex');
}

/** Verify a delegation token signature against an Ed25519 public key (raw 32 bytes) */
function verifyTokenSignature(token: DelegationToken, publicKey: Uint8Array): boolean {
  const payload = createSigningPayload(token);
  const sigBuffer = Buffer.from(token.signature, 'hex');
  const key = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, payload, key, sigBuffer);
}

/** Recursively sort object keys for deterministic serialization */
function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
  }
  return sorted;
}
