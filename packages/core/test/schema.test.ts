import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateAgainstSchema, type ValidationResult } from '../src/schema/validator.js';
import { validateIntentSchema, validatePolicySchema } from '../src/schema/index.js';

// ---------------------------------------------------------------------------
// Load schemas directly for the generic validator tests
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const schemasDir = resolve(__dirname, '..', '..', '..', 'config', 'schemas');

const intentSchema = JSON.parse(
  readFileSync(resolve(schemasDir, 'intent.schema.json'), 'utf-8'),
) as Record<string, unknown>;

const policySchema = JSON.parse(
  readFileSync(resolve(schemasDir, 'policy.schema.json'), 'utf-8'),
) as Record<string, unknown>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validIntent(): Record<string, unknown> {
  return {
    version: '1.0',
    intent_id: 'intent-001',
    agent_did: 'did:key:z6Mktest123',
    timestamp: '2026-02-17T12:00:00.000Z',
    action: {
      type: 'think',
      params: { query: 'hello' },
    },
    context: {
      triggered_by: 'user_message',
      session_id: 'session-001',
    },
    nonce: 42,
    signature: 'abcdef0123456789',
  };
}

function validPolicy(): Record<string, unknown> {
  return {
    version: '1.0',
    tiers: {
      tier_0: {
        description: 'No verification needed',
        actions: ['think', 'recall'],
        verification: 'none',
      },
      tier_1: {
        description: 'Local policy check',
        actions: ['send_message'],
        verification: 'local',
        constraints: {
          recipient_whitelist: true,
          rate_limit: { max: 30, window: '1h' },
        },
      },
      tier_2: {
        description: 'Enhanced verification',
        actions: ['api_call'],
        verification: 'local',
      },
      tier_3: {
        description: 'Human approval required',
        actions: ['transfer_funds'],
        verification: 'human_approval',
        multisig: { required: 1, timeout: '1h' },
      },
    },
    rate_limits: {
      api_call: { max: 50, window: '1h' },
    },
    whitelists: {
      contacts: ['alice@example.com'],
      domains: ['example.com'],
      actions: ['think'],
    },
    blacklists: {
      contacts: ['evil@bad.com'],
      domains: ['bad.com'],
    },
  };
}

// ---------------------------------------------------------------------------
// Intent Schema Tests
// ---------------------------------------------------------------------------

describe('Intent Schema Validation', () => {
  it('valid intent passes schema validation', () => {
    const result = validateIntentSchema(validIntent());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('missing required fields fail', () => {
    const intent = validIntent();
    delete intent.signature;
    delete intent.nonce;
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('"signature"'))).toBe(true);
    expect(result.errors.some(e => e.includes('"nonce"'))).toBe(true);
  });

  it('invalid version fails', () => {
    const intent = validIntent();
    intent.version = '2.0';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('const'))).toBe(true);
  });

  it('invalid agent_did (not starting with "did:") fails', () => {
    const intent = validIntent();
    intent.agent_did = 'key:z6Mktest123';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('pattern'))).toBe(true);
  });

  it('invalid timestamp format fails', () => {
    const intent = validIntent();
    intent.timestamp = 'not-a-date';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('date-time'))).toBe(true);
  });

  it('invalid signature (non-hex) fails', () => {
    const intent = validIntent();
    intent.signature = 'not-hex-!!!';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('pattern'))).toBe(true);
  });

  it('negative nonce fails', () => {
    const intent = validIntent();
    intent.nonce = -1;
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('minimum'))).toBe(true);
  });

  it('extra properties fail (additionalProperties: false)', () => {
    const intent = validIntent();
    (intent as Record<string, unknown>).extra_field = 'nope';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('additional property'))).toBe(true);
  });

  it('valid context passes', () => {
    const intent = validIntent();
    (intent.context as Record<string, unknown>).conversation_hash = 'abc123';
    (intent.context as Record<string, unknown>).parent_intent_id = 'intent-000';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('invalid triggered_by value fails', () => {
    const intent = validIntent();
    (intent.context as Record<string, unknown>).triggered_by = 'manual';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('enum'))).toBe(true);
  });

  it('non-integer nonce fails', () => {
    const intent = validIntent();
    intent.nonce = 3.14;
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('integer'))).toBe(true);
  });

  it('empty intent_id fails', () => {
    const intent = validIntent();
    intent.intent_id = '';
    const result = validateIntentSchema(intent);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('minLength'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Policy Schema Tests
// ---------------------------------------------------------------------------

describe('Policy Schema Validation', () => {
  it('valid PolicyConfig passes schema validation', () => {
    const result = validatePolicySchema(validPolicy());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('missing tiers fail', () => {
    const policy = validPolicy();
    delete policy.tiers;
    const result = validatePolicySchema(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('"tiers"'))).toBe(true);
  });

  it('missing individual tier fails', () => {
    const policy = validPolicy();
    delete (policy.tiers as Record<string, unknown>).tier_2;
    const result = validatePolicySchema(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('"tier_2"'))).toBe(true);
  });

  it('invalid verification value fails', () => {
    const policy = validPolicy();
    const tiers = policy.tiers as Record<string, Record<string, unknown>>;
    tiers.tier_0.verification = 'blockchain';
    const result = validatePolicySchema(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('enum'))).toBe(true);
  });

  it('rate limit validation works', () => {
    const policy = validPolicy();
    (policy.rate_limits as Record<string, unknown>)['bad_action'] = {
      max: 0,
      window: 'invalid',
    };
    const result = validatePolicySchema(policy);
    expect(result.valid).toBe(false);
    // max: 0 fails minimum: 1, window: 'invalid' fails pattern
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
  });

  it('whitelist/blacklist validation works', () => {
    const policy = validPolicy();
    // Valid structure — should pass
    const result1 = validatePolicySchema(policy);
    expect(result1.valid).toBe(true);

    // Invalid: whitelists.contacts should be array of strings
    const bad = validPolicy();
    (bad.whitelists as Record<string, unknown>).contacts = 'not-an-array';
    const result2 = validatePolicySchema(bad);
    expect(result2.valid).toBe(false);
    expect(result2.errors.some(e => e.includes('array'))).toBe(true);
  });

  it('extra properties on policy root fail', () => {
    const policy = validPolicy();
    (policy as Record<string, unknown>).unknown_field = true;
    const result = validatePolicySchema(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('additional property'))).toBe(true);
  });

  it('default-policy.json validates against policy schema', () => {
    const defaultPolicy = JSON.parse(
      readFileSync(resolve(schemasDir, '..', 'default-policy.json'), 'utf-8'),
    );
    const result = validatePolicySchema(defaultPolicy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Generic Validator Tests
// ---------------------------------------------------------------------------

describe('validateAgainstSchema — generic', () => {
  it('validates simple type checks', () => {
    const schema = { type: 'string' };
    expect(validateAgainstSchema('hello', schema).valid).toBe(true);
    expect(validateAgainstSchema(42, schema).valid).toBe(false);
  });

  it('validates nested objects with $ref', () => {
    const schema = {
      type: 'object',
      properties: {
        item: { '$ref': '#/$defs/Item' },
      },
      '$defs': {
        Item: {
          type: 'object',
          required: ['name'],
          properties: {
            name: { type: 'string' },
          },
        },
      },
    };
    expect(validateAgainstSchema({ item: { name: 'test' } }, schema).valid).toBe(true);
    expect(validateAgainstSchema({ item: {} }, schema).valid).toBe(false);
  });

  it('returns multiple errors for multiple violations', () => {
    const result = validateIntentSchema({});
    // Missing all 8 required fields
    expect(result.errors.length).toBeGreaterThanOrEqual(8);
  });
});
