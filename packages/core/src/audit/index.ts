export * from './types.js';
export * from './local-logger.js';
export { AuditAnchor } from './anchor.js';
export { AnchoredAuditLogger } from './anchored-logger.js';
export {
  buildMerkleTree,
  generateMerkleProof,
  verifyMerkleProof,
  hashAuditEntry,
} from './merkle.js';
export type { AnchorConfig, AnchorResult, InclusionProof } from './anchor.js';
