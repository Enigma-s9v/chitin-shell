// Trust Delegation — Barrel Exports

export { DelegationManager } from './delegation.js';
export type { CreateDelegationParams } from './delegation.js';
export { MemoryTrustStore } from './store.js';
export { intersectScopes, scopeAllowsAction, isSubScope, validateScope } from './scope.js';
export type {
  DelegationScope,
  DelegationToken,
  TrustChain,
  DelegationResult,
  TrustStoreEntry,
  ITrustStore,
} from './types.js';
