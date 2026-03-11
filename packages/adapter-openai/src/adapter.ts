import type { AgentAction, AgentActionResult, IProtocolAdapter } from "@varcore/core";
import type { OpenAIFunctionCall, OpenAIToolResult } from "./types";

/**
 * OpenAIAdapter implements IProtocolAdapter for the OpenAI function-calling wire format.
 *
 * toAction() parses the function.arguments JSON string (as returned by the OpenAI API)
 * into a Record<string, unknown>. Throws SyntaxError if the string is malformed —
 * callers (wrapOpenAI, NonSudoCallbackHandler) should catch and emit a dead_letter_receipt.
 *
 * toResponse() converts an AgentActionResult back to an OpenAI-compatible tool result.
 */
export class OpenAIAdapter
  implements IProtocolAdapter<OpenAIFunctionCall, OpenAIToolResult>
{
  toAction(call: OpenAIFunctionCall): AgentAction {
    const rawArgs = call.function.arguments;
    let args: Record<string, unknown>;

    if (rawArgs === undefined || rawArgs === null) {
      args = {};
    } else if (typeof rawArgs === "string") {
      // Throws SyntaxError on malformed JSON — caller should catch and emit dead_letter_receipt
      args = JSON.parse(rawArgs) as Record<string, unknown>;
    } else {
      args = rawArgs;
    }

    return {
      tool_name: call.function.name,
      arguments: args,
      protocol: "openai",
      raw: call,
    };
  }

  toResponse(result: AgentActionResult): OpenAIToolResult {
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
