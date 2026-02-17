/**
 * TEE (Trusted Execution Environment) — Type Definitions
 *
 * Abstraction over hardware TEE environments (Intel SGX, AMD SEV, AWS Nitro Enclaves, etc.).
 * Provides attestation, sealed storage, and code measurement primitives.
 */

export type TeeProvider = 'sgx' | 'sev' | 'nitro' | 'trustzone' | 'mock' | 'none';

export interface TeeAttestation {
  provider: TeeProvider;
  /** Base64-encoded attestation quote */
  quote: string;
  /** ISO timestamp */
  timestamp: string;
  measurements: TeeMeasurement[];
  /** Provider-specific signature */
  signature: string;
}

export interface TeeMeasurement {
  /** e.g., 'code_hash', 'config_hash', 'enclave_id' */
  name: string;
  /** Hex-encoded measurement value */
  value: string;
  /** e.g., 'sha256', 'sha384' */
  algorithm: string;
}

export interface TeeConfig {
  provider: TeeProvider;
  /** Remote attestation endpoint */
  attestationEndpoint?: string;
  /** Re-attestation interval in seconds (default: 3600) */
  refreshInterval?: number;
  /** Use mock TEE if real TEE not available (default: false in prod) */
  fallbackToMock?: boolean;
}

export interface TeeCapabilities {
  provider: TeeProvider;
  available: boolean;
  /** Can seal/unseal data */
  sealingSupported: boolean;
  /** Can generate attestation quotes */
  attestationSupported: boolean;
  /** Has secure memory enclave */
  secureMemory: boolean;
  /** Maximum secure memory in MB */
  maxMemoryMb: number;
}

export interface ITeeProvider {
  /** Get provider capabilities */
  getCapabilities(): Promise<TeeCapabilities>;

  /** Generate attestation quote */
  attest(userData?: string): Promise<TeeAttestation>;

  /** Verify an attestation from another enclave */
  verifyAttestation(attestation: TeeAttestation): Promise<boolean>;

  /** Seal data (encrypt with TEE-bound key) */
  seal(data: Buffer, label?: string): Promise<Buffer>;

  /** Unseal data (decrypt with TEE-bound key) */
  unseal(sealed: Buffer, label?: string): Promise<Buffer>;

  /** Measure code integrity (hash of running code) */
  measure(code: string | Buffer): Promise<TeeMeasurement>;
}
