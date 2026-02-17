/**
 * Lightweight Metrics Collection — Production Monitoring
 *
 * In-memory counters, gauges, and histograms.
 * Zero external dependencies. Exports to Prometheus text format.
 */

export interface MetricPoint {
  name: string;
  value: number;
  timestamp: number;
  labels?: Record<string, string>;
}

export type MetricType = 'counter' | 'gauge' | 'histogram';

export interface MetricDefinition {
  name: string;
  type: MetricType;
  description: string;
  labels?: string[];
}

export class MetricsCollector {
  private counters: Map<string, number>;
  private gauges: Map<string, number>;
  private histograms: Map<string, number[]>;
  private definitions: Map<string, MetricDefinition>;

  constructor() {
    this.counters = new Map();
    this.gauges = new Map();
    this.histograms = new Map();
    this.definitions = new Map();
  }

  /** Define a metric */
  define(def: MetricDefinition): void {
    this.definitions.set(def.name, def);

    // Initialize storage
    switch (def.type) {
      case 'counter':
        this.counters.set(def.name, 0);
        break;
      case 'gauge':
        this.gauges.set(def.name, 0);
        break;
      case 'histogram':
        this.histograms.set(def.name, []);
        break;
    }
  }

  /** Counter: increment */
  increment(name: string, value = 1, _labels?: Record<string, string>): void {
    const current = this.counters.get(name) ?? 0;
    this.counters.set(name, current + value);
  }

  /** Gauge: set */
  set(name: string, value: number): void {
    this.gauges.set(name, value);
  }

  /** Histogram: observe */
  observe(name: string, value: number): void {
    const arr = this.histograms.get(name);
    if (arr) {
      arr.push(value);
    } else {
      this.histograms.set(name, [value]);
    }
  }

  /** Get current value */
  getValue(name: string): number | number[] | undefined {
    if (this.counters.has(name)) return this.counters.get(name);
    if (this.gauges.has(name)) return this.gauges.get(name);
    if (this.histograms.has(name)) return this.histograms.get(name);
    return undefined;
  }

  /** Get all metrics as points */
  getAll(): MetricPoint[] {
    const now = Date.now();
    const points: MetricPoint[] = [];

    for (const [name, value] of this.counters) {
      points.push({ name, value, timestamp: now });
    }

    for (const [name, value] of this.gauges) {
      points.push({ name, value, timestamp: now });
    }

    for (const [name, values] of this.histograms) {
      // For histogram, report count as the point value
      points.push({ name, value: values.length, timestamp: now });
    }

    return points;
  }

  /** Get histogram percentile */
  getPercentile(name: string, p: number): number | undefined {
    const values = this.histograms.get(name);
    if (!values || values.length === 0) return undefined;

    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  /** Reset all metrics */
  reset(): void {
    for (const [name] of this.counters) {
      this.counters.set(name, 0);
    }
    for (const [name] of this.gauges) {
      this.gauges.set(name, 0);
    }
    for (const [name] of this.histograms) {
      this.histograms.set(name, []);
    }
  }

  /** Export as Prometheus-compatible text format */
  toPrometheus(): string {
    const lines: string[] = [];

    for (const [name, def] of this.definitions) {
      lines.push(`# HELP ${name} ${def.description}`);
      lines.push(`# TYPE ${name} ${def.type}`);

      switch (def.type) {
        case 'counter': {
          const value = this.counters.get(name) ?? 0;
          lines.push(`${name} ${value}`);
          break;
        }
        case 'gauge': {
          const value = this.gauges.get(name) ?? 0;
          lines.push(`${name} ${value}`);
          break;
        }
        case 'histogram': {
          const values = this.histograms.get(name) ?? [];
          const count = values.length;
          const sum = values.reduce((a, b) => a + b, 0);
          lines.push(`${name}_count ${count}`);
          lines.push(`${name}_sum ${sum}`);
          break;
        }
      }
    }

    return lines.join('\n') + '\n';
  }

  /** Pre-defined Shell metrics */
  static createShellMetrics(): MetricsCollector {
    const collector = new MetricsCollector();

    collector.define({ name: 'chitin_intents_total', type: 'counter', description: 'Total intents processed' });
    collector.define({ name: 'chitin_intents_approved', type: 'counter', description: 'Total intents approved' });
    collector.define({ name: 'chitin_intents_rejected', type: 'counter', description: 'Total intents rejected' });
    collector.define({ name: 'chitin_policy_check_duration_ms', type: 'histogram', description: 'Policy check duration in milliseconds' });
    collector.define({ name: 'chitin_execution_duration_ms', type: 'histogram', description: 'Execution duration in milliseconds' });
    collector.define({ name: 'chitin_sanitization_detections', type: 'counter', description: 'Total sanitization detections' });
    collector.define({ name: 'chitin_active_delegations', type: 'gauge', description: 'Currently active delegations' });
    collector.define({ name: 'chitin_a2a_messages_sent', type: 'counter', description: 'Total A2A messages sent' });
    collector.define({ name: 'chitin_a2a_messages_received', type: 'counter', description: 'Total A2A messages received' });
    collector.define({ name: 'chitin_proof_generation_duration_ms', type: 'histogram', description: 'Proof generation duration in milliseconds' });

    return collector;
  }
}
