import type { IntentV1 } from './types.js';
import { verifySignature } from './signer.js';

const VALID_TRIGGERS = ['user_message', 'scheduled', 'webhook', 'agent_internal'] as const;
const HEX_PATTERN = /^[0-9a-f]+$/i;

export function validateIntentStructure(intent: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (intent === null || typeof intent !== 'object') {
    return { valid: false, errors: ['Intent must be a non-null object'] };
  }

  const i = intent as Record<string, unknown>;

  if (i.version !== '1.0') {
    errors.push('version must be "1.0"');
  }

  if (typeof i.intent_id !== 'string' || i.intent_id.length === 0) {
    errors.push('intent_id must be a non-empty string');
  }

  if (typeof i.agent_did !== 'string' || !i.agent_did.startsWith('did:')) {
    errors.push('agent_did must be a string starting with "did:"');
  }

  if (typeof i.timestamp !== 'string' || isNaN(Date.parse(i.timestamp))) {
    errors.push('timestamp must be a valid ISO date string');
  }

  validateAction(i.action, errors);
  validateContext(i.context, errors);

  if (typeof i.nonce !== 'number' || !Number.isInteger(i.nonce) || i.nonce <= 0) {
    errors.push('nonce must be a positive integer');
  }

  if (typeof i.signature !== 'string' || i.signature.length === 0 || !HEX_PATTERN.test(i.signature)) {
    errors.push('signature must be a non-empty hex string');
  }

  return { valid: errors.length === 0, errors };
}

export function validateIntent(
  intent: IntentV1,
  publicKey: Uint8Array,
): { valid: boolean; errors: string[] } {
  const structural = validateIntentStructure(intent);
  if (!structural.valid) {
    return structural;
  }

  const errors: string[] = [];

  if (!verifySignature(intent, publicKey)) {
    errors.push('Signature verification failed');
  }

  return { valid: errors.length === 0, errors };
}

function validateAction(action: unknown, errors: string[]): void {
  if (action === null || typeof action !== 'object') {
    errors.push('action must be an object');
    return;
  }

  const a = action as Record<string, unknown>;

  if (typeof a.type !== 'string' || a.type.length === 0) {
    errors.push('action.type must be a non-empty string');
  }

  if (a.params === null || typeof a.params !== 'object' || Array.isArray(a.params)) {
    errors.push('action.params must be an object');
  }
}

function validateContext(context: unknown, errors: string[]): void {
  if (context === null || typeof context !== 'object') {
    errors.push('context must be an object');
    return;
  }

  const c = context as Record<string, unknown>;

  if (!VALID_TRIGGERS.includes(c.triggered_by as typeof VALID_TRIGGERS[number])) {
    errors.push(`context.triggered_by must be one of: ${VALID_TRIGGERS.join(', ')}`);
  }

  if (typeof c.session_id !== 'string' || c.session_id.length === 0) {
    errors.push('context.session_id must be a non-empty string');
  }
}
