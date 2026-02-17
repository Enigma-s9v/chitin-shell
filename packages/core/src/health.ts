/**
 * Health Check System — Production Monitoring
 *
 * Provides health status for all Shell subsystems.
 * Zero external dependencies — uses built-in timers and in-memory state.
 */

import type { PolicyEngine } from './policy/engine.js';
import type { IVault } from './proxy/types.js';
import type { IAuditLogger } from './audit/types.js';

export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

export interface HealthCheck {
  name: string;
  status: HealthStatus;
  message?: string;
  latencyMs?: number;
  /** ISO timestamp */
  lastChecked: string;
}

export interface HealthReport {
  /** Overall: worst of all checks */
  status: HealthStatus;
  /** Seconds since start */
  uptime: number;
  /** Package version */
  version: string;
  checks: HealthCheck[];
  /** ISO timestamp */
  timestamp: string;
}

const STATUS_PRIORITY: Record<HealthStatus, number> = {
  healthy: 0,
  degraded: 1,
  unhealthy: 2,
};

export class HealthMonitor {
  private startTime: number;
  private checks: Map<string, () => Promise<HealthCheck>>;

  constructor() {
    this.startTime = Date.now();
    this.checks = new Map();
  }

  /** Register a named health check */
  register(name: string, check: () => Promise<HealthCheck>): void {
    this.checks.set(name, check);
  }

  /** Remove a health check */
  unregister(name: string): void {
    this.checks.delete(name);
  }

  /** Run all checks and return report */
  async getReport(): Promise<HealthReport> {
    const results: HealthCheck[] = [];

    for (const [, check] of this.checks) {
      try {
        results.push(await check());
      } catch (err) {
        results.push({
          name: 'unknown',
          status: 'unhealthy',
          message: err instanceof Error ? err.message : String(err),
          lastChecked: new Date().toISOString(),
        });
      }
    }

    // Overall status: worst of all checks
    let worstStatus: HealthStatus = 'healthy';
    for (const result of results) {
      if (STATUS_PRIORITY[result.status] > STATUS_PRIORITY[worstStatus]) {
        worstStatus = result.status;
      }
    }

    return {
      status: worstStatus,
      uptime: (Date.now() - this.startTime) / 1000,
      version: '0.1.0-alpha.0',
      checks: results,
      timestamp: new Date().toISOString(),
    };
  }

  /** Quick overall status (no details) */
  async getStatus(): Promise<HealthStatus> {
    const report = await this.getReport();
    return report.status;
  }

  /** Built-in check: PolicyEngine */
  static policyEngineCheck(engine: PolicyEngine): () => Promise<HealthCheck> {
    return async () => {
      const start = Date.now();
      try {
        const policy = engine.getPolicy();
        const hasTiers = policy.tiers !== undefined;
        return {
          name: 'policy_engine',
          status: hasTiers ? 'healthy' : 'degraded',
          message: hasTiers ? 'Policy loaded with tier configuration' : 'Missing tier configuration',
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      } catch (err) {
        return {
          name: 'policy_engine',
          status: 'unhealthy',
          message: err instanceof Error ? err.message : String(err),
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      }
    };
  }

  /** Built-in check: Vault */
  static vaultCheck(vault: IVault): () => Promise<HealthCheck> {
    return async () => {
      const start = Date.now();
      try {
        // Simple canary: list keys to verify vault is operational
        await vault.list();
        return {
          name: 'vault',
          status: 'healthy',
          message: 'Vault is operational',
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      } catch (err) {
        return {
          name: 'vault',
          status: 'unhealthy',
          message: err instanceof Error ? err.message : String(err),
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      }
    };
  }

  /** Built-in check: AuditLogger */
  static auditLogCheck(logger: IAuditLogger): () => Promise<HealthCheck> {
    return async () => {
      const start = Date.now();
      try {
        // Attempt a minimal query to verify the logger is operational
        await logger.query({ last: 1 });
        return {
          name: 'audit_log',
          status: 'healthy',
          message: 'Audit logger is operational',
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      } catch (err) {
        return {
          name: 'audit_log',
          status: 'unhealthy',
          message: err instanceof Error ? err.message : String(err),
          latencyMs: Date.now() - start,
          lastChecked: new Date().toISOString(),
        };
      }
    };
  }
}
