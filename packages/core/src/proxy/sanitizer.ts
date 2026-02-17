import type { SanitizationPattern } from './types.js';

const DEFAULT_PATTERNS: SanitizationPattern[] = [
  // More specific patterns first — order matters!
  { name: 'anthropic_key', pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, replacement: '[REDACTED:anthropic_key]' },
  { name: 'openai_key', pattern: /sk-[a-zA-Z0-9_-]{20,}/g, replacement: '[REDACTED:openai_key]' },
  { name: 'google_ai_key', pattern: /AIza[a-zA-Z0-9_-]{35}/g, replacement: '[REDACTED:google_ai_key]' },
  { name: 'aws_key', pattern: /AKIA[A-Z0-9]{16}/g, replacement: '[REDACTED:aws_key]' },
  { name: 'github_token', pattern: /gh[pos]_[a-zA-Z0-9]{20,}/g, replacement: '[REDACTED:github_token]' },
  { name: 'slack_token', pattern: /xox[bpras]-[a-zA-Z0-9-]+/g, replacement: '[REDACTED:slack_token]' },
  { name: 'jwt', pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, replacement: '[REDACTED:jwt]' },
  { name: 'bearer_token', pattern: /Bearer [a-zA-Z0-9._-]+/g, replacement: '[REDACTED:bearer_token]' },
  { name: 'connection_string', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s]+/g, replacement: '[REDACTED:connection_string]' },
  // Generic patterns last — these are broad catch-alls
  { name: 'generic_secret', pattern: /(?:password|secret|api[_-]?key)\s*[=:]\s*['"]?[^\s'"]+/gi, replacement: '[REDACTED:generic_secret]' },
];

interface SanitizeResult {
  output: string;
  redacted_count: number;
  redacted_types: string[];
}

interface SanitizeObjectResult {
  output: unknown;
  redacted_count: number;
  redacted_types: string[];
}

export class Sanitizer {
  private patterns: SanitizationPattern[];

  constructor(additionalPatterns: SanitizationPattern[] = []) {
    this.patterns = [...DEFAULT_PATTERNS, ...additionalPatterns];
  }

  sanitize(input: string): SanitizeResult {
    let output = input;
    let redacted_count = 0;
    const redacted_types = new Set<string>();

    for (const { name, pattern, replacement } of this.patterns) {
      // Reset lastIndex for stateful regexes (global flag)
      const regex = new RegExp(pattern.source, pattern.flags);
      const matches = output.match(regex);
      if (matches) {
        redacted_count += matches.length;
        redacted_types.add(name);
        output = output.replace(regex, replacement);
      }
    }

    return { output, redacted_count, redacted_types: Array.from(redacted_types) };
  }

  sanitizeObject(obj: unknown): SanitizeObjectResult {
    let total_redacted = 0;
    const all_types = new Set<string>();

    const traverse = (value: unknown): unknown => {
      if (typeof value === 'string') {
        const result = this.sanitize(value);
        total_redacted += result.redacted_count;
        for (const t of result.redacted_types) all_types.add(t);
        return result.output;
      }

      if (Array.isArray(value)) {
        return value.map(item => traverse(item));
      }

      if (value !== null && typeof value === 'object') {
        const clone: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) {
          clone[k] = traverse(v);
        }
        return clone;
      }

      return value;
    };

    const output = traverse(obj);
    return { output, redacted_count: total_redacted, redacted_types: Array.from(all_types) };
  }
}
