// Values
export {
  OpenAIAdapter,
  createActionReceipt,
} from "@varcore/adapter-openai";

// Types
export type {
  OpenAIFunctionCall,
  OpenAIToolResult,
  OpenAIAdapterConfig,
  CreateActionReceiptParams,
} from "@varcore/adapter-openai";

// wrapOpenAI is intentionally excluded — it throws at runtime.
// Re-add once implemented in @varcore/adapter-openai.
