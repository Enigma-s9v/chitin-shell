/**
 * CLI Utilities
 *
 * Shared helpers for config loading, shell creation, and ANSI formatting.
 * Zero external dependencies — Node.js built-ins only.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ChitinShell, loadDefaultPolicy } from '@chitin-id/shell-core';
import type { PolicyConfig } from '@chitin-id/shell-core';

// ---------------------------------------------------------------------------
// ANSI Color Helpers (no chalk dependency)
// ---------------------------------------------------------------------------

const isColorSupported =
  process.env.NO_COLOR === undefined && process.env.FORCE_COLOR !== '0';

function wrap(code: string, text: string): string {
  if (!isColorSupported) return text;
  return `\x1b[${code}m${text}\x1b[0m`;
}

export const color = {
  bold: (text: string) => wrap('1', text),
  dim: (text: string) => wrap('2', text),
  red: (text: string) => wrap('31', text),
  green: (text: string) => wrap('32', text),
  yellow: (text: string) => wrap('33', text),
  blue: (text: string) => wrap('34', text),
  magenta: (text: string) => wrap('35', text),
  cyan: (text: string) => wrap('36', text),
  white: (text: string) => wrap('37', text),
  gray: (text: string) => wrap('90', text),
  bgRed: (text: string) => wrap('41', text),
  bgGreen: (text: string) => wrap('42', text),
  bgYellow: (text: string) => wrap('43', text),
  bgBlue: (text: string) => wrap('44', text),
} as const;

// ---------------------------------------------------------------------------
// Tier Colors
// ---------------------------------------------------------------------------

const TIER_COLORS = [color.green, color.yellow, color.magenta, color.red] as const;

export function tierColor(tier: number): (text: string) => string {
  return TIER_COLORS[tier] ?? color.red;
}

export function tierLabel(tier: number): string {
  const labels = ['TIER 0', 'TIER 1', 'TIER 2', 'TIER 3'];
  const label = labels[tier] ?? `TIER ${tier}`;
  return tierColor(tier)(label);
}

// ---------------------------------------------------------------------------
// Config Types & Loading
// ---------------------------------------------------------------------------

export interface ChitinConfig {
  policy: string;
  auditDir: string;
}

const CONFIG_FILENAME = 'chitin.config.json';
const DEFAULT_POLICY_FILENAME = 'chitin-policy.json';

export function getConfigFilename(): string {
  return CONFIG_FILENAME;
}

export function getDefaultPolicyFilename(): string {
  return DEFAULT_POLICY_FILENAME;
}

export async function loadConfig(cwd?: string): Promise<ChitinConfig> {
  const dir = cwd ?? process.cwd();
  const configPath = join(dir, CONFIG_FILENAME);

  let raw: string;
  try {
    raw = await readFile(configPath, 'utf-8');
  } catch {
    throw new Error(
      `No ${CONFIG_FILENAME} found in ${dir}. Run 'chitin-shell init' first.`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${configPath} contains invalid JSON`);
  }

  const obj = parsed as Record<string, unknown>;
  return {
    policy: (obj.policy as string) ?? DEFAULT_POLICY_FILENAME,
    auditDir: (obj.auditDir as string) ?? '.chitin-shell/audit',
  };
}

// ---------------------------------------------------------------------------
// Shell Creation
// ---------------------------------------------------------------------------

export async function createShellFromConfig(cwd?: string): Promise<ChitinShell> {
  const dir = cwd ?? process.cwd();
  const config = await loadConfig(dir);
  const policyPath = join(dir, config.policy);
  const auditDir = join(dir, config.auditDir);

  return ChitinShell.create({
    policy: policyPath,
    auditDir,
  });
}

// ---------------------------------------------------------------------------
// Policy Loading (with fallback)
// ---------------------------------------------------------------------------

export async function loadPolicyForDisplay(filePath?: string): Promise<PolicyConfig> {
  if (filePath) {
    const raw = await readFile(filePath, 'utf-8');
    return JSON.parse(raw) as PolicyConfig;
  }

  // Try to load from config
  try {
    const config = await loadConfig();
    const policyPath = join(process.cwd(), config.policy);
    const raw = await readFile(policyPath, 'utf-8');
    return JSON.parse(raw) as PolicyConfig;
  } catch {
    // Fall back to default policy
    return loadDefaultPolicy();
  }
}

// ---------------------------------------------------------------------------
// Arg Parsing Helpers
// ---------------------------------------------------------------------------

export function parseFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

export function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

// ---------------------------------------------------------------------------
// Table Formatting
// ---------------------------------------------------------------------------

export function padRight(str: string, width: number): string {
  if (str.length >= width) return str;
  return str + ' '.repeat(width - str.length);
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}
