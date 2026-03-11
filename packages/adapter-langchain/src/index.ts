export { LangChainAdapter } from "./adapter";
export type { LangChainToolCall, LangChainToolResult, LangChainAdapterConfig } from "./types";
export { NonSudoCallbackHandler } from "./handler";

import { NonSudoCallbackHandler } from "./handler";
import type { LangChainAdapterConfig } from "./types";

/**
 * createNonSudoCallbacks — convenience factory that returns a callbacks array
 * containing a single NonSudoCallbackHandler, ready to pass to any LangChain runnable.
 *
 * Usage:
 *   const llm = new ChatOpenAI({
 *     callbacks: createNonSudoCallbacks(config),
 *   });
 */
export function createNonSudoCallbacks(
  config: LangChainAdapterConfig
): NonSudoCallbackHandler[] {
  return [new NonSudoCallbackHandler(config)];
}
