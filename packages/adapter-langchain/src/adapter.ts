import type { AgentAction, AgentActionResult, IProtocolAdapter } from "@varcore/core";
import type { LangChainToolCall, LangChainToolResult } from "./types";

/**
 * LangChainAdapter implements IProtocolAdapter for the LangChain tool-call format.
 *
 * toAction() normalizes LangChain tool arguments (parsed Record or JSON string)
 * into a Record<string, unknown>. Throws SyntaxError if a JSON string is malformed —
 * callers (NonSudoCallbackHandler) should catch and emit a dead_letter_receipt.
 *
 * toResponse() converts an AgentActionResult back to a LangChain-compatible result.
 */
export class LangChainAdapter
  implements IProtocolAdapter<LangChainToolCall, LangChainToolResult>
{
  toAction(call: LangChainToolCall): AgentAction {
    let args: Record<string, unknown>;

    if (typeof call.args === "string") {
      // Throws SyntaxError on malformed JSON — caller should handle
      args = JSON.parse(call.args) as Record<string, unknown>;
    } else {
      args = call.args ?? {};
    }

    return {
      tool_name: call.name,
      arguments: args,
      protocol: "langchain",
      raw: call,
    };
  }

  toResponse(result: AgentActionResult): LangChainToolResult {
    if (!result.success) {
      return {
        content: result.error ?? "Tool call failed",
        isError: true,
      };
    }
    const content =
      typeof result.content === "string"
        ? result.content
        : JSON.stringify(result.content ?? "");
    return { content };
  }
}
