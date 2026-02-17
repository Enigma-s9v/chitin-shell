/**
 * Intent Layer — Type Definitions
 *
 * An Intent is the ONLY output format an LLM can produce that will be acted upon.
 * It is a structured, signed data structure — never a raw API call.
 */

/** Security tiers from no-check (0) to human-approval-required (3) */
export type SecurityTier = 0 | 1 | 2 | 3;

/** Predefined action types mapped to security tiers */
export type ActionType =
  // Tier 0: Read-only & internal
  | 'think'
  | 'recall'
  | 'summarize'
  | 'read_file'
  | 'read_email'
  // Tier 1: Low-risk write (whitelisted targets)
  | 'send_message'
  | 'reply_email'
  | 'post_channel'
  // Tier 2: Higher-risk operations
  | 'send_email_new'
  | 'file_write'
  | 'api_call'
  | 'create_issue'
  // Tier 3: Critical operations
  | 'transfer_funds'
  | 'change_permissions'
  | 'bulk_export'
  | 'system_config'
  // Allow custom action types (default to Tier 3)
  | (string & {});

/** The action the LLM wants to perform */
export interface IntentAction {
  type: ActionType;
  params: Record<string, unknown>;
}

/** Context about how this Intent was triggered */
export interface IntentContext {
  triggered_by: 'user_message' | 'scheduled' | 'webhook' | 'agent_internal';
  session_id: string;
  conversation_hash?: string;
  parent_intent_id?: string;
}

/** A fully signed Intent (v1.0) */
export interface IntentV1 {
  version: '1.0';
  intent_id: string;
  agent_did: string;
  timestamp: string;
  action: IntentAction;
  context: IntentContext;
  nonce: number;
  signature: string;
}

/** An Intent before signing */
export type UnsignedIntent = Omit<IntentV1, 'signature'>;

/** Parameters for creating a new Intent */
export interface CreateIntentParams {
  action: ActionType;
  params: Record<string, unknown>;
  context?: Partial<IntentContext>;
}

/** Key pair for signing Intents (Ed25519) */
export interface AgentKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  did: string;
}
