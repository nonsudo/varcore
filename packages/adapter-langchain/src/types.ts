/**
 * Local LangChain types for the NonSudo adapter.
 * The adapter works with @langchain/core as a peerDependency.
 */

export interface LangChainToolCall {
  /** The tool/function name. */
  name: string;
  /**
   * The arguments for the tool call.
   * LangChain may pass these as a parsed Record or as a JSON string.
   */
  args: Record<string, unknown> | string;
  /** Optional tool run ID for correlation. */
  id?: string;
}

export type LangChainToolResult = {
  content: string;
  isError?: boolean;
};

export interface LangChainAdapterConfig {
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
