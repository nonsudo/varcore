/**
 * WorkflowSession — manages the receipt chain for one NonSudo workflow.
 *
 * Created lazily by NonSudoCallbackHandler on the first tool call.
 * Writes a workflow_manifest on init, then chains action_receipt / dead_letter_receipt
 * for each subsequent tool invocation.
 *
 * TODO(refactor): receipt-creation logic duplicates adapter-openai/src/receipt.ts.
 * Extract to a shared helper once a cross-adapter package is introduced.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
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
import type { LangChainAdapterConfig } from "./types";
import { SimpleReceiptWriter } from "./writer";

function paramsCanonicalHash(params: unknown): string {
  const canonical = canonicalize(params as object) ?? "null";
  const hex = crypto.createHash("sha256").update(canonical).digest("hex");
  return "sha256:" + hex;
}

function nowRfc3339(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export class WorkflowSession {
  private workflowId: string;
  private prevReceipt: SignedReceipt;
  private writer: SimpleReceiptWriter;
  private keypair: { privateKey: Uint8Array; keyId: string };
  private agentId: string;
  private policyBundleHash: string;

  private constructor(
    workflowId: string,
    prevReceipt: SignedReceipt,
    writer: SimpleReceiptWriter,
    keypair: { privateKey: Uint8Array; keyId: string },
    agentId: string,
    policyBundleHash: string
  ) {
    this.workflowId = workflowId;
    this.prevReceipt = prevReceipt;
    this.writer = writer;
    this.keypair = keypair;
    this.agentId = agentId;
    this.policyBundleHash = policyBundleHash;
  }

  static async create(config: LangChainAdapterConfig): Promise<WorkflowSession> {
    // Load private key from key_path (hex-encoded, one line)
    const privHex = fs.readFileSync(config.key_path, "utf8").trim();
    const privateKey = new Uint8Array(Buffer.from(privHex, "hex"));
    // Derive keyId from filename (e.g. "01ABC.key" → "01ABC")
    const keyId = path.basename(config.key_path, ".key");

    const workflowId = ulid();
    const policyBundleHash = config.policy_bundle_hash ?? "sha256:" + "0".repeat(64);
    const writer = new SimpleReceiptWriter(config.receipt_file);

    // Write workflow_manifest (sequence_number = 0, prev_receipt_hash = null)
    const manifestFields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: config.agent_id,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: config.initiator_id,
      workflow_owner: config.workflow_owner,
      session_budget: config.session_budget ?? { api_calls: 1000 },
      declared_tools: [],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
    };

    const unsigned = createReceipt(manifestFields);
    const signed = await signReceipt(unsigned, privateKey, keyId);
    writer.append(signed);

    return new WorkflowSession(
      workflowId,
      signed,
      writer,
      { privateKey, keyId },
      config.agent_id,
      policyBundleHash
    );
  }

  async emitActionReceipt(
    toolName: string,
    args: Record<string, unknown>,
    decision: Decision = "ALLOW",
    decisionReason: string = "langchain tool call",
    blastRadius: BlastRadius = "LOW",
    reversible: boolean = true
  ): Promise<SignedReceipt> {
    const stateVersionBefore = this.prevReceipt.sequence_number;
    const stateVersionAfter =
      decision === "ALLOW" || decision === "FAIL_OPEN"
        ? stateVersionBefore + 1
        : stateVersionBefore;

    const fields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: this.workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: this.agentId,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: this.policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: toolName,
      params_canonical_hash: paramsCanonicalHash(args),
      decision,
      decision_reason: decisionReason,
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: blastRadius,
      reversible,
      state_version_before: stateVersionBefore,
      state_version_after: stateVersionAfter,
      response_hash: null,
    };

    const unsigned = createReceipt(fields);
    const chained = chainReceipt(unsigned, this.prevReceipt);
    const signed = await signReceipt(chained, this.keypair.privateKey, this.keypair.keyId);
    this.writer.append(signed);
    this.prevReceipt = signed;
    return signed;
  }

  async emitDeadLetter(
    toolName: string,
    args: Record<string, unknown>,
    failureReason: string,
    fallbackPolicy: FallbackPolicy = "fail_closed"
  ): Promise<SignedReceipt> {
    const stateVersionBefore = this.prevReceipt.sequence_number;

    const fields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: this.workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: this.agentId,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: this.policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: toolName,
      params_canonical_hash: paramsCanonicalHash(args),
      decision: "FAIL_CLOSED",
      decision_reason: failureReason,
      decision_order: 1,
      queue_status: "DEAD_LETTER",
      queue_timeout_ms: 5000,
      blast_radius: "CRITICAL",
      reversible: false,
      state_version_before: stateVersionBefore,
      state_version_after: stateVersionBefore,
      response_hash: null,
      failure_reason: failureReason,
      fallback_policy: fallbackPolicy,
    };

    const unsigned = createReceipt(fields);
    const chained = chainReceipt(unsigned, this.prevReceipt);
    const signed = await signReceipt(chained, this.keypair.privateKey, this.keypair.keyId);
    this.writer.append(signed);
    this.prevReceipt = signed;
    return signed;
  }

  close(): void {
    this.writer.close();
  }
}
