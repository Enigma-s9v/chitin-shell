import type { RateLimitRule } from './types.js';

function parseWindow(window: string): number {
  const match = window.match(/^(\d+)(m|h)$/);
  if (!match) throw new Error(`Invalid rate limit window: ${window}`);

  const value = parseInt(match[1], 10);
  const unit = match[2];

  if (unit === 'm') return value * 60_000;
  return value * 3_600_000;
}

export class RateLimiter {
  private entries: Map<string, number[]> = new Map();

  check(
    agentDid: string,
    actionType: string,
    rule: RateLimitRule,
  ): { allowed: boolean; remaining: number; reset_at: number } {
    const key = `${agentDid}:${actionType}`;
    const windowMs = parseWindow(rule.window);
    const now = Date.now();
    const cutoff = now - windowMs;

    const timestamps = (this.entries.get(key) ?? []).filter((t) => t > cutoff);
    this.entries.set(key, timestamps);

    const count = timestamps.length;
    const allowed = count < rule.max;
    const remaining = Math.max(0, rule.max - count);
    const reset_at = timestamps.length > 0 ? timestamps[0] + windowMs : now + windowMs;

    return { allowed, remaining, reset_at };
  }

  record(agentDid: string, actionType: string): void {
    const key = `${agentDid}:${actionType}`;
    const timestamps = this.entries.get(key) ?? [];
    timestamps.push(Date.now());
    this.entries.set(key, timestamps);
  }

  reset(agentDid?: string): void {
    if (!agentDid) {
      this.entries.clear();
      return;
    }
    const prefix = `${agentDid}:`;
    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix)) {
        this.entries.delete(key);
      }
    }
  }
}
