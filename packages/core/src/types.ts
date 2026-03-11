/**
 * Protocol-agnostic representation of a single agent tool call,
 * as seen by the NonSudo proxy before any policy evaluation.
 *
 * Every protocol adapter (MCP, OpenAI, LangChain, A2A) must produce
 * one of these before the call reaches the proxy core.
 */
export interface AgentAction {
  /** The tool/function name being invoked. */
  tool_name: string;

  /** The raw arguments passed to the tool. Opaque to the proxy core. */
  arguments: Record<string, unknown>;

  /**
   * The protocol this action came from.
   * Used for receipt metadata and future protocol-specific logic.
   * Adapters must set this; the proxy core never infers it.
   */
  protocol: "mcp" | "openai" | "langchain" | "a2a" | string;

  /**
   * Optional: the raw transport-level message, for adapters that need
   * to pass it downstream unchanged. Typed as unknown — the proxy
   * core must never inspect this.
   */
  raw?: unknown;
}

/**
 * The result of a tool call, as returned by the upstream MCP server
 * or other protocol endpoint.
 */
export interface AgentActionResult {
  /**
   * Whether the upstream call succeeded.
   * Adapters must normalise this — the proxy core never reads raw transport errors.
   */
  success: boolean;

  /** The raw response payload. Opaque to the proxy core. */
  content?: unknown;

  /** If success is false, a human-readable error string. */
  error?: string;

  /**
   * The raw transport-level response, preserved for pass-through.
   * Typed as unknown — the proxy core must never inspect this.
   */
  raw?: unknown;
}

/**
 * An adapter converts a protocol-specific inbound message into an
 * AgentAction, and converts an AgentActionResult back into the
 * protocol-specific response format.
 *
 * The proxy core calls `toAction` on the way in and `toResponse` on the way out.
 */
export interface IProtocolAdapter<TRequest = unknown, TResponse = unknown> {
  /** Convert a protocol-specific request to a protocol-agnostic AgentAction. */
  toAction(request: TRequest): AgentAction;

  /** Convert an AgentActionResult back into a protocol-specific response. */
  toResponse(result: AgentActionResult): TResponse;
}
