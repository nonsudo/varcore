import { canonicalHash } from "./canonical-hash";

export interface AgentClassInput {
  /**
   * The system prompt given to the agent. Trimmed before hashing.
   */
  systemPrompt: string;

  /**
   * Tool names the agent has access to.
   * Each name is trimmed. Duplicates are removed. Array is sorted.
   * Order and duplicates in the input do not affect the output.
   */
  toolNames: string[];

  /**
   * Model identifier, e.g. "claude-sonnet-4-6". Trimmed before hashing.
   */
  modelId: string;
}

/**
 * Compute a stable, reproducible identifier for an agent class.
 *
 * An agent class is defined by its system prompt, tool set, and model version.
 * Any change to any of these three inputs produces a different agent_class_id.
 *
 * Normalization applied before hashing:
 * - systemPrompt and modelId are trimmed
 * - toolNames are individually trimmed, deduplicated via Set, and sorted
 *
 * Truncation note: the full SHA-256 is 64 hex chars; we keep 32 for a compact
 * URL-safe identifier. Collision probability is negligible for realistic agent
 * class counts but is not cryptographic-strength. If agent_class_id becomes a
 * long-lived external identifier in legal or financial contexts, consider using
 * the full 64-char hex instead.
 *
 * @returns "cls_" + first 32 hex chars of SHA-256(JCS-canonical JSON)
 */
export function computeAgentClassId(input: AgentClassInput): string {
  const canonical = {
    model: input.modelId.trim(),
    prompt: input.systemPrompt.trim(),
    tools: [...new Set(input.toolNames.map((t) => t.trim()))].sort(),
  };

  const hash = canonicalHash(canonical);
  const hex = hash.slice("sha256:".length);
  return "cls_" + hex.slice(0, 32);
}
