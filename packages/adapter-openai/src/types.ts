/**
 * Local OpenAI types — no openai SDK runtime dependency.
 * Matches the wire format returned by the OpenAI API for function/tool calls.
 */

export interface OpenAIFunctionCall {
  /** Tool call ID returned by the OpenAI API. */
  id?: string;
  type?: "function";
  function: {
    /** The name of the function/tool. */
    name: string;
    /**
     * The arguments for the function call.
     * The OpenAI API returns this as a JSON-encoded string.
     * The adapter also accepts a pre-parsed object for convenience.
     */
    arguments?: string | Record<string, unknown>;
  };
}

export interface OpenAIToolResult {
  tool_call_id?: string;
  role?: "tool";
  content: string;
  isError?: boolean;
}

export interface OpenAIAdapterConfig {
  agent_id: string;
  workflow_owner: string;
  initiator_id: string;
  session_budget?: Record<string, number>;
  /** Path to the NDJSON receipt output file. */
  receipt_file: string;
  /** Path to the hex-encoded Ed25519 private key file (.key). */
  key_path: string;
  policy_bundle_hash?: string;
}
