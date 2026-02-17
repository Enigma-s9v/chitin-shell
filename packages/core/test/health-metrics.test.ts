import { describe, it, expect, beforeEach } from 'vitest';
import { HealthMonitor } from '../src/health.js';
import type { HealthCheck, HealthStatus } from '../src/health.js';
import { MetricsCollector } from '../src/metrics.js';
import { validateShellConfig } from '../src/config-validator.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { MemoryVault } from '../src/proxy/vault.js';
import { LocalAuditLogger } from '../src/audit/local-logger.js';
import { loadDefaultPolicy } from '../src/policy/loader.js';
import type { ChitinShellOptions } from '../src/shell.js';

// ---------------------------------------------------------------------------
// HealthMonitor
// ---------------------------------------------------------------------------
describe('HealthMonitor', () => {
  let monitor: HealthMonitor;

  beforeEach(() => {
    monitor = new HealthMonitor();
  });

  it('register and getReport', async () => {
    monitor.register('test', async () => ({
      name: 'test',
      status: 'healthy' as HealthStatus,
      message: 'all good',
      lastChecked: new Date().toISOString(),
    }));

    const report = await monitor.getReport();
    expect(report.checks).toHaveLength(1);
    expect(report.checks[0].name).toBe('test');
    expect(report.checks[0].status).toBe('healthy');
    expect(report.version).toBe('0.1.0-alpha.0');
    expect(report.timestamp).toBeTruthy();
  });

  it('healthy status when all checks pass', async () => {
    monitor.register('a', async () => ({
      name: 'a',
      status: 'healthy' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));
    monitor.register('b', async () => ({
      name: 'b',
      status: 'healthy' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));

    const report = await monitor.getReport();
    expect(report.status).toBe('healthy');
  });

  it('degraded when one check is degraded', async () => {
    monitor.register('ok', async () => ({
      name: 'ok',
      status: 'healthy' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));
    monitor.register('slow', async () => ({
      name: 'slow',
      status: 'degraded' as HealthStatus,
      message: 'High latency',
      lastChecked: new Date().toISOString(),
    }));

    const report = await monitor.getReport();
    expect(report.status).toBe('degraded');
  });

  it('unhealthy when one check is unhealthy', async () => {
    monitor.register('ok', async () => ({
      name: 'ok',
      status: 'healthy' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));
    monitor.register('dead', async () => ({
      name: 'dead',
      status: 'unhealthy' as HealthStatus,
      message: 'Connection refused',
      lastChecked: new Date().toISOString(),
    }));

    const report = await monitor.getReport();
    expect(report.status).toBe('unhealthy');
  });

  it('unregister removes check', async () => {
    monitor.register('removeme', async () => ({
      name: 'removeme',
      status: 'unhealthy' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));
    monitor.unregister('removeme');

    const report = await monitor.getReport();
    expect(report.checks).toHaveLength(0);
    expect(report.status).toBe('healthy');
  });

  it('getStatus returns quick result', async () => {
    monitor.register('simple', async () => ({
      name: 'simple',
      status: 'degraded' as HealthStatus,
      lastChecked: new Date().toISOString(),
    }));

    const status = await monitor.getStatus();
    expect(status).toBe('degraded');
  });

  it('uptime increases', async () => {
    const report1 = await monitor.getReport();
    await new Promise((r) => setTimeout(r, 50));
    const report2 = await monitor.getReport();

    expect(report2.uptime).toBeGreaterThanOrEqual(report1.uptime);
  });

  it('policyEngineCheck returns healthy for valid engine', async () => {
    const policy = loadDefaultPolicy();
    const engine = new PolicyEngine(policy);
    const check = HealthMonitor.policyEngineCheck(engine);
    const result = await check();

    expect(result.name).toBe('policy_engine');
    expect(result.status).toBe('healthy');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it('vaultCheck returns healthy for valid vault', async () => {
    const vault = new MemoryVault();
    const check = HealthMonitor.vaultCheck(vault);
    const result = await check();

    expect(result.name).toBe('vault');
    expect(result.status).toBe('healthy');
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------
describe('MetricsCollector', () => {
  let collector: MetricsCollector;

  beforeEach(() => {
    collector = new MetricsCollector();
  });

  it('increment counter', () => {
    collector.define({ name: 'requests', type: 'counter', description: 'Total requests' });
    collector.increment('requests');
    collector.increment('requests');
    collector.increment('requests', 3);

    expect(collector.getValue('requests')).toBe(5);
  });

  it('set gauge', () => {
    collector.define({ name: 'active', type: 'gauge', description: 'Active connections' });
    collector.set('active', 10);
    expect(collector.getValue('active')).toBe(10);

    collector.set('active', 5);
    expect(collector.getValue('active')).toBe(5);
  });

  it('observe histogram', () => {
    collector.define({ name: 'latency', type: 'histogram', description: 'Latency in ms' });
    collector.observe('latency', 10);
    collector.observe('latency', 20);
    collector.observe('latency', 30);

    const values = collector.getValue('latency');
    expect(Array.isArray(values)).toBe(true);
    expect(values).toEqual([10, 20, 30]);
  });

  it('getValue returns current value', () => {
    collector.define({ name: 'count', type: 'counter', description: 'A counter' });
    collector.increment('count', 42);

    expect(collector.getValue('count')).toBe(42);
    expect(collector.getValue('nonexistent')).toBeUndefined();
  });

  it('getAll returns all metrics', () => {
    collector.define({ name: 'c', type: 'counter', description: 'counter' });
    collector.define({ name: 'g', type: 'gauge', description: 'gauge' });
    collector.define({ name: 'h', type: 'histogram', description: 'histogram' });

    collector.increment('c', 5);
    collector.set('g', 42);
    collector.observe('h', 100);

    const all = collector.getAll();
    expect(all.length).toBe(3);

    const names = all.map((p) => p.name);
    expect(names).toContain('c');
    expect(names).toContain('g');
    expect(names).toContain('h');
  });

  it('getPercentile returns correct value', () => {
    collector.define({ name: 'dur', type: 'histogram', description: 'Duration' });
    // Add values 1 through 100
    for (let i = 1; i <= 100; i++) {
      collector.observe('dur', i);
    }

    expect(collector.getPercentile('dur', 50)).toBe(50);
    expect(collector.getPercentile('dur', 95)).toBe(95);
    expect(collector.getPercentile('dur', 99)).toBe(99);
    expect(collector.getPercentile('dur', 100)).toBe(100);
  });

  it('getPercentile returns undefined for empty histogram', () => {
    collector.define({ name: 'empty', type: 'histogram', description: 'Empty' });
    expect(collector.getPercentile('empty', 50)).toBeUndefined();
  });

  it('reset clears all values', () => {
    collector.define({ name: 'c', type: 'counter', description: 'counter' });
    collector.define({ name: 'g', type: 'gauge', description: 'gauge' });
    collector.define({ name: 'h', type: 'histogram', description: 'histogram' });

    collector.increment('c', 10);
    collector.set('g', 20);
    collector.observe('h', 30);

    collector.reset();

    expect(collector.getValue('c')).toBe(0);
    expect(collector.getValue('g')).toBe(0);
    expect(collector.getValue('h')).toEqual([]);
  });

  it('toPrometheus outputs valid format', () => {
    collector.define({ name: 'test_counter', type: 'counter', description: 'A test counter' });
    collector.define({ name: 'test_gauge', type: 'gauge', description: 'A test gauge' });
    collector.define({ name: 'test_histogram', type: 'histogram', description: 'A test histogram' });

    collector.increment('test_counter', 5);
    collector.set('test_gauge', 42);
    collector.observe('test_histogram', 10);
    collector.observe('test_histogram', 20);

    const output = collector.toPrometheus();

    expect(output).toContain('# HELP test_counter A test counter');
    expect(output).toContain('# TYPE test_counter counter');
    expect(output).toContain('test_counter 5');

    expect(output).toContain('# HELP test_gauge A test gauge');
    expect(output).toContain('# TYPE test_gauge gauge');
    expect(output).toContain('test_gauge 42');

    expect(output).toContain('# HELP test_histogram A test histogram');
    expect(output).toContain('# TYPE test_histogram histogram');
    expect(output).toContain('test_histogram_count 2');
    expect(output).toContain('test_histogram_sum 30');
  });

  it('createShellMetrics has all predefined metrics', () => {
    const metrics = MetricsCollector.createShellMetrics();

    const expectedNames = [
      'chitin_intents_total',
      'chitin_intents_approved',
      'chitin_intents_rejected',
      'chitin_policy_check_duration_ms',
      'chitin_execution_duration_ms',
      'chitin_sanitization_detections',
      'chitin_active_delegations',
      'chitin_a2a_messages_sent',
      'chitin_a2a_messages_received',
      'chitin_proof_generation_duration_ms',
    ];

    for (const name of expectedNames) {
      // Each metric should be defined and have an initial value
      expect(metrics.getValue(name)).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// ConfigValidation
// ---------------------------------------------------------------------------
describe('ConfigValidation', () => {
  it('validates valid config', () => {
    const options: ChitinShellOptions = {
      policy: loadDefaultPolicy(),
      zkp: { enabled: true, provenance: true, nonLeakage: true },
    };
    const result = validateShellConfig(options);

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('catches invalid RPC URL', () => {
    const options: ChitinShellOptions = {
      onChain: {
        rpcUrl: 'not-a-url',
        contractAddress: '0x1234567890123456789012345678901234567890',
        chainId: 8453,
      },
    };
    const result = validateShellConfig(options);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('rpcUrl'))).toBe(true);
  });

  it('catches invalid contract address', () => {
    const options: ChitinShellOptions = {
      onChain: {
        rpcUrl: 'https://mainnet.base.org',
        contractAddress: 'not-an-address',
        chainId: 8453,
      },
    };
    const result = validateShellConfig(options);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('contractAddress'))).toBe(true);
  });

  it('catches invalid chain ID in DID resolver', () => {
    const options: ChitinShellOptions = {
      didResolver: {
        rpcUrl: 'https://mainnet.base.org',
        registryAddress: '0x1234567890123456789012345678901234567890',
        chainId: -1,
      },
    };
    const result = validateShellConfig(options);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('chainId'))).toBe(true);
  });

  it('warns for non-json policy file extension', () => {
    const options: ChitinShellOptions = {
      policy: '/path/to/policy.yaml',
    };
    const result = validateShellConfig(options);

    // This should be a warning, not an error
    expect(result.warnings.some((w) => w.includes('.json'))).toBe(true);
  });

  it('catches invalid rate limit values', () => {
    const options: ChitinShellOptions = {
      policy: {
        tiers: {
          tier_0: { description: 'read', verification: 'none', actions: [] },
          tier_1: {
            description: 'write',
            verification: 'local',
            actions: [],
            constraints: {
              rate_limit: { max: -5, window: '1h' },
            },
          },
          tier_2: { description: 'sensitive', verification: 'on_chain', actions: [] },
          tier_3: { description: 'critical', verification: 'human', actions: [] },
        },
      },
    };
    const result = validateShellConfig(options);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('rate_limit.max'))).toBe(true);
  });
});
