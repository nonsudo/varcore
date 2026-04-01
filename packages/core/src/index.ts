export type { AgentAction, AgentActionResult, IProtocolAdapter } from "./types";
export type { SigningProvider, PublicKeyJwk } from "./signing-provider";
export { canonicalHash } from "./canonical-hash";
export { computeAgentClassId } from "./agent-class-id";
export type { AgentClassInput } from "./agent-class-id";
export { varcoreLog } from "./logger";
export type { LogLevel, VarcoreLogEntry } from "./logger";

import { canonicalHash } from "./canonical-hash";

/**
 * computeContentEntropyHash — canonical hash of string content,
 * with JSON-parse-first semantics for deterministic object hashing.
 *
 * If `content` is a valid JSON object or array, it is parsed first so that
 * key ordering in the raw string does not affect the hash (JCS sorts keys).
 * JSON primitives (numbers, strings, booleans, null) and non-JSON strings
 * are hashed as-is via canonicalHash.
 *
 * Used for response_hash on action_receipts and upstream_response_digest
 * on post_receipts. Extracted from adapter-langchain to ensure all
 * consumers produce identical hashes for the same content.
 *
 * @param content - The raw string content (e.g. upstream tool response).
 * @returns "sha256:<64 lowercase hex chars>"
 */
export function computeContentEntropyHash(content: string): string {
  // JSON.parse-first: if content is a valid JSON object,
  // canonicalise the parsed object so key ordering in the
  // raw string does not affect the hash.
  // Falls back to raw string for primitives and non-JSON.
  let value: unknown;
  try {
    const parsed = JSON.parse(content);
    if (parsed !== null && typeof parsed === "object") {
      value = parsed;
    } else {
      value = content;
    }
  } catch {
    value = content;
  }
  return canonicalHash(value);
}
