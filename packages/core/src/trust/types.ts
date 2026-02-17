/**
 * Trust Delegation Layer — Type Definitions
 *
 * Multi-agent trust delegation allows agents to delegate a subset of their
 * permissions to other agents, creating verifiable chains of trust.
 */

import type { ActionType, SecurityTier } from '../intent/types.js';

/** Defines the boundaries of what a delegate is allowed to do */
export interface DelegationScope {
  /** Allowed actions (must be a subset of delegator's permissions) */
  actions: ActionType[];
  /** Maximum security tier level allowed */
  maxTier: SecurityTier;
  /** Optional: restrict to specific targets */
  targets?: string[];
  /** How many levels of sub-delegation allowed (0 = no sub-delegation) */
  maxDepth: number;
  /** Optional rate limiting */
  rateLimit?: {
    max: number;
    windowSeconds: number;
  };
}

/** A signed delegation token granting specific permissions to another agent */
export interface DelegationToken {
  /** Unique token ID (UUID) */
  id: string;
  /** Token format version */
  version: 1;
  /** DID of the delegating agent */
  delegator: string;
  /** DID of the receiving agent */
  delegate: string;
  /** Permissions granted */
  scope: DelegationScope;
  /** ISO timestamp — when this token was created */
  issuedAt: string;
  /** ISO timestamp — when this token expires */
  expiresAt: string;
  /** If this is a sub-delegation, the parent token's ID */
  parentTokenId?: string;
  /** Ed25519 signature by delegator (hex-encoded) */
  signature: string;
}

/** An ordered chain of delegation tokens from root authority to leaf agent */
export interface TrustChain {
  /** Ordered: root delegation -> leaf delegation */
  tokens: DelegationToken[];
  /** DID of the original authority */
  rootAgent: string;
  /** DID of the final delegatee */
  leafAgent: string;
  /** Intersection of all scopes in chain */
  effectiveScope: DelegationScope;
}

/** Result of validating a delegation or trust chain */
export interface DelegationResult {
  valid: boolean;
  reason: string;
  chain?: TrustChain;
  effectiveScope?: DelegationScope;
}

/** A stored delegation entry with revocation tracking */
export interface TrustStoreEntry {
  token: DelegationToken;
  revoked: boolean;
  revokedAt?: string;
}

/** Interface for persisting and querying delegation tokens */
export interface ITrustStore {
  store(token: DelegationToken): Promise<void>;
  get(tokenId: string): Promise<TrustStoreEntry | null>;
  getByDelegate(delegateDid: string): Promise<TrustStoreEntry[]>;
  getByDelegator(delegatorDid: string): Promise<TrustStoreEntry[]>;
  revoke(tokenId: string): Promise<void>;
  isRevoked(tokenId: string): Promise<boolean>;
}
