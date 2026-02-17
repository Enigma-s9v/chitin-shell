// Secure Tool Wrapper
export { createSecureTool, createSecureTools, ChitinToolRejectionError } from './secure-tool.js';

// Callback Handler
export { ChitinCallbackHandler } from './callback-handler.js';

// Types
export type {
  // LangChain-compatible interfaces
  LangChainToolCall,
  LangChainCallbackHandler as LangChainCallbackHandlerInterface,
  // Tool definitions
  ToolDefinition,
  // Chitin adapter config
  ChitinToolConfig,
  ChitinLangChainOptions,
  SecureToolOptions,
  // Interception tracking
  ToolCallInterception,
} from './types.js';
