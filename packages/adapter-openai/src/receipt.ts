/**
 * createActionReceipt — manual API for creating signed VAR action receipts
 * from the OpenAI adapter context.
 *
 * Handles both COMPLETED and DEAD_LETTER queue_status based on whether
 * failureReason is provided.
 */

import * as crypto from "crypto";
import { ulid } from "ulid";
import canonicalize from "canonicalize";
import { createReceipt, signReceipt, chainReceipt } from "@varcore/receipts";
import type {
  SignedReceipt,
  ReceiptFields,
  Decision,
  BlastRadius,
  FallbackPolicy,
} from "@varcore/receipts";

function paramsCanonicalHash(params: unknown): string {
  const canonical = canonicalize(params as object) ?? "null";
  const hex = crypto.createHash("sha256").update(canonical).digest("hex");
  return "sha256:" + hex;
}

function nowRfc3339(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface CreateActionReceiptParams {
  agentId: string;
  workflowId: string;
  toolName: string;
  args: Record<string, unknown>;
  decision: Decision;
  decisionReason: string;
  blastRadius: BlastRadius;
  reversible: boolean;
  policyBundleHash: string;
  /** The previous signed receipt to chain from. */
  prevReceipt: SignedReceipt;
  keypair: { privateKey: Uint8Array; keyId: string };
  /** If provided, creates a DEAD_LETTER receipt instead of COMPLETED. */
  failureReason?: string;
  fallbackPolicy?: FallbackPolicy;
}

export async function createActionReceipt(
  params: CreateActionReceiptParams
): Promise<SignedReceipt> {
  const {
    agentId,
    workflowId,
    toolName,
    args,
    decision,
    decisionReason,
    blastRadius,
    reversible,
    policyBundleHash,
    prevReceipt,
    keypair,
    failureReason,
    fallbackPolicy,
  } = params;

  const isDeadLetter = failureReason !== undefined;
  const stateVersionBefore = prevReceipt.sequence_number;
  const stateVersionAfter =
    decision === "ALLOW" || decision === "FAIL_OPEN"
      ? stateVersionBefore + 1
      : stateVersionBefore;

  const baseFields = {
    receipt_id: ulid(),
    record_type: "action_receipt" as const,
    spec_version: "var/1.0" as const,
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated" as const,
    agent_id: agentId,
    issued_at: nowRfc3339(),
    prev_receipt_hash: null as string | null,
    sequence_number: 0,
    policy_bundle_hash: policyBundleHash,
    rfc3161_token: null as string | null,
    tsa_id: null as string | null,
    tool_name: toolName,
    params_canonical_hash: paramsCanonicalHash(args),
    decision,
    decision_reason: decisionReason,
    decision_order: 1,
    queue_timeout_ms: 5000,
    blast_radius: blastRadius,
    reversible,
    state_version_before: stateVersionBefore,
    state_version_after: stateVersionAfter,
    response_hash: null as string | null,
  };

  const fields: ReceiptFields = isDeadLetter
    ? {
        ...baseFields,
        queue_status: "DEAD_LETTER" as const,
        failure_reason: failureReason ?? "unknown failure reason",
        fallback_policy: fallbackPolicy ?? "fail_closed",
      }
    : { ...baseFields, queue_status: "COMPLETED" as const };

  const unsigned = createReceipt(fields);
  const chained = chainReceipt(unsigned, prevReceipt);
  return signReceipt(chained, keypair.privateKey, keypair.keyId);
}
