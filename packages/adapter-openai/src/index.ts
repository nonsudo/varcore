export { OpenAIAdapter } from "./adapter";
export type { OpenAIFunctionCall, OpenAIToolResult, OpenAIAdapterConfig } from "./types";
export { createActionReceipt } from "./receipt";
export type { CreateActionReceiptParams } from "./receipt";

/**
 * wrapOpenAI — wraps an OpenAI-compatible client to intercept function calls
 * and emit VAR receipts for each tool invocation.
 *
 * Phase 0: returns the client unchanged (receipt emission deferred to Phase 1).
 *
 * @param client   Any object with a chat.completions.create method
 * @param _config  Adapter configuration (agent_id, key_path, receipt_file, etc.)
 * @returns        The client unchanged in Phase 0
 *
 * TODO(phase-1): intercept client.chat.completions.create, parse tool_calls,
 * emit action_receipt or dead_letter_receipt for each, chain receipts correctly.
 */
export function wrapOpenAI<T>(client: T, _config: import("./types").OpenAIAdapterConfig): T {
  return client;
}
