/**
 * A2A Middleware — Integrates A2A communication with ChitinShell
 *
 * Provides ActionMapper for outgoing A2A requests and secure handler
 * wrapping for incoming messages through the Shell policy pipeline.
 */

import type { ActionMapper, IVault } from '../proxy/types.js';
import type { ChitinShell } from '../shell.js';
import type { A2AHandler } from './server.js';
import type { A2AMessage, A2APayload } from './types.js';
import { A2AClient } from './client.js';

/**
 * Creates an ActionMapper that routes 'a2a_request' actions through the A2A client.
 *
 * Expected params:
 *  - target_did: string — The DID of the target agent
 *  - method: string — The A2A method to invoke
 *  - params?: Record<string, unknown> — Method parameters
 */
export function createA2AMapper(client: A2AClient): ActionMapper {
  return {
    action_type: 'a2a_request',

    async execute(
      params: Record<string, unknown>,
      _vault: IVault,
    ): Promise<unknown> {
      const targetDid = params.target_did as string;
      const method = params.method as string;
      const methodParams = params.params as Record<string, unknown> | undefined;

      if (!targetDid || !method) {
        throw new Error('a2a_request requires target_did and method params');
      }

      const response = await client.request(targetDid, method, methodParams);

      return {
        message_id: response.id,
        from: response.from,
        type: response.type,
        payload: response.payload,
      };
    },
  };
}

/**
 * Wraps an A2A handler so that incoming messages are verified through
 * the ChitinShell policy pipeline before reaching the actual handler.
 *
 * The incoming A2A message is converted to a Shell Intent with:
 *  - action.type = 'a2a_request'
 *  - action.params = { from, method, params }
 *  - context.triggered_by = 'webhook'
 */
export function createSecureA2AHandler(
  shell: ChitinShell,
  handler: A2AHandler,
): A2AHandler {
  return async (message: A2AMessage): Promise<A2APayload> => {
    // Create an intent from the A2A message for policy verification
    const intent = shell.createIntent({
      action: 'a2a_request',
      params: {
        from: message.from,
        method: message.payload.method,
        params: message.payload.params,
      },
      context: {
        triggered_by: 'webhook',
        session_id: message.id,
      },
    });

    // Run through Shell policy
    const result = await shell.execute(intent);

    if (!result.verification.approved) {
      return {
        method: message.payload.method,
        error: {
          code: 403,
          message: `Policy rejected: ${result.verification.reason}`,
        },
      };
    }

    if (result.verification.requires_human) {
      return {
        method: message.payload.method,
        error: {
          code: 403,
          message: 'Requires human approval',
        },
      };
    }

    // Policy approved — delegate to actual handler
    return handler(message);
  };
}
