/**
 * Schema Validation — Barrel Exports
 *
 * Pre-loaded schema validation functions for Intent and Policy configs.
 * Schemas are loaded from JSON files at runtime using Node.js fs module.
 */

export { validateAgainstSchema } from './validator.js';
export type { ValidationResult } from './validator.js';

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateAgainstSchema, type ValidationResult } from './validator.js';

// Resolve schema directory relative to this file.
// At runtime this file lives in dist/schema/index.js or src/schema/index.ts
// — either way we walk up to packages/core then to shell/config/schemas.
const __dirname = dirname(fileURLToPath(import.meta.url));

function loadSchema(filename: string): Record<string, unknown> {
  // Walk up: schema/ -> src/ -> core/ -> packages/ -> shell/ -> config/schemas/
  const schemaPath = resolve(__dirname, '..', '..', '..', '..', 'config', 'schemas', filename);
  return JSON.parse(readFileSync(schemaPath, 'utf-8')) as Record<string, unknown>;
}

// Lazy-loaded singletons
let _intentSchema: Record<string, unknown> | null = null;
let _policySchema: Record<string, unknown> | null = null;

function getIntentSchema(): Record<string, unknown> {
  if (!_intentSchema) _intentSchema = loadSchema('intent.schema.json');
  return _intentSchema;
}

function getPolicySchema(): Record<string, unknown> {
  if (!_policySchema) _policySchema = loadSchema('policy.schema.json');
  return _policySchema;
}

/**
 * Validate an object against the Chitin Intent v1.0 schema.
 */
export function validateIntentSchema(intent: unknown): ValidationResult {
  return validateAgainstSchema(intent, getIntentSchema());
}

/**
 * Validate an object against the Chitin Policy schema.
 */
export function validatePolicySchema(policy: unknown): ValidationResult {
  return validateAgainstSchema(policy, getPolicySchema());
}
