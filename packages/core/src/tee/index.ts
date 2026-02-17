// TEE (Trusted Execution Environment) — Barrel Exports

export type {
  TeeProvider,
  TeeAttestation,
  TeeMeasurement,
  TeeConfig,
  TeeCapabilities,
  ITeeProvider,
} from './types.js';

export { MockTeeProvider } from './mock-provider.js';
export { TeeVault } from './tee-vault.js';
