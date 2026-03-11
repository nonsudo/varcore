import * as fs from "fs";
import * as ed from "@noble/ed25519";
import { createHash } from "crypto";
import canonicalize from "canonicalize";
import type { SigningProvider } from "@varcore/core";
import { AsnConvert } from "@peculiar/asn1-schema";
import { TimeStampResp, PKIStatus, TSTInfo } from "@peculiar/asn1-tsp";
import { SignedData } from "@peculiar/asn1-cms";
import {
  ReceiptFields,
  SignedReceipt,
  UnsignedReceipt,
  SignatureBlock,
  ChainError,
  ChainWarning,
  ChainVerificationResult,
  TsaRecord,
  L3Result,
  L4Result,
  L4Violation,
  L4ViolationCode,
  isValidKeyId,
} from "./types";
// The new receipt type interfaces and signed types are re-exported below via
// "export type { ... } from './types'" — no local usage needed here.

// Re-export all types so consumers can import from "@varcore/receipts" directly
export type {
  ReceiptFields,
  SignedReceipt,
  UnsignedReceipt,
  SignatureBlock,
  RecordType,
  WorkflowIdSource,
  Decision,
  QueueStatus,
  BlastRadius,
  FallbackPolicy,
  CloseReason,
  // Named signed subtypes — enable TypeScript narrowing via record_type discriminant
  SignedWorkflowManifest,
  SignedActionReceipt,
  SignedDeadLetterReceipt,
  SignedWorkflowClosed,
  // VAR-Money v1.0 / Walk mode new signed types (Session A)
  SignedPostReceipt,
  SignedRecoveryEvent,
  SignedBudgetWarning,
  SignedReservationExpired,
  // Group 3: STEP_UP approval engine
  SignedApprovalReceipt,
  ApprovalReceiptFields,
  ApprovalOutcome,
  PostReceiptFields,
  RecoveryEventFields,
  BudgetWarningFields,
  ReservationExpiredFields,
  // VAR-Money v1.0 enumerations
  DeploymentMode,
  TaxonomyStatus,
  BillableReason,
  TerminalOutcome,
  IndexStatus,
  RecoveryMethod,
  ReservationReason,
  // Structured chain error types and informational warnings
  ChainError,
  ChainErrorCode,
  ChainVerificationResult,
  ChainWarning,
  ChainWarningCode,
  // L3 types
  TsaRecord,
  L3Status,
  L3Result,
  // L4 types
  L4Status,
  L4ViolationCode,
  L4Violation,
  L4Result,
} from "./types";
// isValidKeyId is a value (function), not a type — export with plain export
export { isValidKeyId } from "./types";
export type { SigningProvider, PublicKeyJwk } from "@varcore/core";

// ---------------------------------------------------------------------------
// Signed-field lists per record_type (Section 3)
// Fields marked signed=yes in the contract. Excludes: signature (n/a),
// rfc3161_token (no), tsa_id (no).
// ---------------------------------------------------------------------------

const BASE_SIGNED_FIELDS = [
  "receipt_id",
  "record_type",
  "spec_version",
  "workflow_id",
  "workflow_id_source",
  "agent_id",
  "issued_at",
  "prev_receipt_hash",
  "sequence_number",
  "policy_bundle_hash",
] as const;

const ACTION_RECEIPT_SIGNED_FIELDS = [
  ...BASE_SIGNED_FIELDS,
  "tool_name",
  "params_canonical_hash",
  "decision",
  "decision_reason",
  "decision_order",
  "queue_status",
  "queue_timeout_ms",
  "blast_radius",
  "reversible",
  "state_version_before",
  "state_version_after",
  "response_hash",
  "upstream_call_initiated",
  // VAR-Money v1.0 / Session A new signed fields
  "money_action",
  "amount_minor_units",
  "billable",
  "billable_reason",
] as const;

// DEAD_LETTER additional fields (only when queue_status === "DEAD_LETTER")
const DEAD_LETTER_EXTRA_FIELDS = [
  "failure_reason",
  "fallback_policy",
] as const;

const WORKFLOW_MANIFEST_SIGNED_FIELDS = [
  ...BASE_SIGNED_FIELDS,
  "initiator_id",
  "workflow_owner",
  "session_budget",
  "declared_tools",
  "capability_manifest_hash",
  "parent_workflow_id",
  "framework_ref",
  "declared_tools_fetch_failed",
  // VAR-Money v1.0 / Session A new signed fields
  "mode",
  "taxonomy_status",
  "money_action_overrides",
] as const;

// ── New receipt type signed field lists (VAR-Money v1.0 / Session A) ──────────

const POST_RECEIPT_SIGNED_FIELDS = [
  "post_receipt_id",
  "record_type",
  "spec_version",
  "pre_receipt_id",
  "workflow_id",
  "agent_id",
  "sequence_number",
  "prev_receipt_hash",
  "policy_bundle_hash",
  "tool_name",
  "terminal_outcome",
  "upstream_response_digest",
  "projection_id",
  "projection_hash",
  "idempotency_key",
  "tool_call_correlation_id",
  "execution_start_ms",
  "execution_end_ms",
  "degraded_reason",
  "billable",
  "billable_reason",
  "issued_at",
  "account_context", // D-1 Session A: required for RI-7 idempotency dedup scope
] as const;

const RECOVERY_EVENT_SIGNED_FIELDS = [
  "recovery_event_id",
  "record_type",
  "spec_version",
  "workflow_id",
  "agent_id",
  "sequence_number",
  "prev_receipt_hash",
  "policy_bundle_hash",
  "recovered_open_pres_count",
  "index_status",
  "recovery_method",
  "scan_window_minutes",
  "scan_receipts_examined",
  "issued_at",
] as const;

const BUDGET_WARNING_SIGNED_FIELDS = [
  "budget_warning_id",
  "record_type",
  "spec_version",
  "workflow_id",
  "agent_id",
  "sequence_number",
  "prev_receipt_hash",
  "policy_bundle_hash",
  "tool_name",
  "spent",
  "reserved",
  "cap",
  "threshold_pct",
  "issued_at",
] as const;

const RESERVATION_EXPIRED_SIGNED_FIELDS = [
  "reservation_expired_id",
  "record_type",
  "spec_version",
  "workflow_id",
  "agent_id",
  "sequence_number",
  "prev_receipt_hash",
  "policy_bundle_hash",
  "pre_receipt_id",
  "amount_released",
  "currency",
  "reason",
  "issued_at",
] as const;

const WORKFLOW_CLOSED_SIGNED_FIELDS = [
  ...BASE_SIGNED_FIELDS,
  "total_calls",
  "total_blocked",
  "total_spend",
  "session_duration_ms",
  "close_reason",
] as const;

// ---------------------------------------------------------------------------
// Build the signing payload object from a receipt
// ---------------------------------------------------------------------------

function buildSigningPayload(receipt: ReceiptFields): Record<string, unknown> {
  const r = receipt as unknown as Record<string, unknown>;
  let fields: readonly string[];

  if (receipt.record_type === "workflow_manifest") {
    fields = WORKFLOW_MANIFEST_SIGNED_FIELDS;
  } else if (receipt.record_type === "action_receipt") {
    const base = ACTION_RECEIPT_SIGNED_FIELDS as readonly string[];
    if (r["queue_status"] === "DEAD_LETTER") {
      fields = [...base, ...DEAD_LETTER_EXTRA_FIELDS];
    } else {
      fields = base;
    }
  } else if (receipt.record_type === "post_receipt") {
    fields = POST_RECEIPT_SIGNED_FIELDS;
  } else if (receipt.record_type === "recovery_event") {
    fields = RECOVERY_EVENT_SIGNED_FIELDS;
  } else if (receipt.record_type === "budget_warning") {
    fields = BUDGET_WARNING_SIGNED_FIELDS;
  } else if (receipt.record_type === "reservation_expired") {
    fields = RESERVATION_EXPIRED_SIGNED_FIELDS;
  } else {
    // workflow_closed
    fields = WORKFLOW_CLOSED_SIGNED_FIELDS;
  }

  const payload: Record<string, unknown> = {};
  for (const key of fields) {
    if (key in r) {
      payload[key] = r[key];
    }
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha256PrefixedHex(data: string): string {
  return "sha256:" + sha256Hex(data);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * createReceipt — validates and returns the fields as an UnsignedReceipt.
 * In v0.1 this is essentially a type-safe pass-through. No signature added.
 */
export function createReceipt(fields: ReceiptFields): UnsignedReceipt {
  return { ...fields };
}

/**
 * signReceipt — computes the JCS-canonical signing payload, signs with Ed25519,
 * and attaches the signature block. Returns a SignedReceipt.
 *
 * Signing rule (Section 5):
 * 1. Build object of only signed=yes fields for this record_type
 * 2. Canonicalize with JCS (canonicalize package, RFC 8785)
 * 3. Sign canonical bytes with Ed25519 (@noble/ed25519)
 * 4. Encode 64-byte sig as base64url, store in signature.sig
 */
export async function signReceipt(
  receipt: UnsignedReceipt,
  signerOrKey: SigningProvider | Uint8Array,
  keyId?: string
): Promise<SignedReceipt> {
  const payload = buildSigningPayload(receipt);

  const canonical = canonicalize(payload);
  if (!canonical) {
    throw new Error("canonicalize returned undefined for signing payload");
  }

  const canonicalBytes = Buffer.from(canonical, "utf8");

  let sigBytes: Uint8Array;
  let resolvedKeyId: string;

  if (signerOrKey instanceof Uint8Array) {
    sigBytes = await ed.signAsync(canonicalBytes, signerOrKey);
    resolvedKeyId = keyId ?? "nonsudo-key-1";
  } else {
    sigBytes = await signerOrKey.sign(canonicalBytes);
    resolvedKeyId = signerOrKey.keyId;
  }

  // base64url encode (no padding)
  const sig = Buffer.from(sigBytes).toString("base64url");

  const signature: SignatureBlock = {
    alg: "Ed25519",
    key_id: resolvedKeyId,
    sig,
  };

  return { ...receipt, signature } as SignedReceipt;
}

/**
 * chainReceipt — sets prev_receipt_hash and sequence_number on an unsigned
 * receipt based on the previous signed receipt.
 *
 * Chaining rule (Section 6):
 * prev_receipt_hash = "sha256:" + SHA-256(JCS(complete_previous_receipt_object))
 * sequence_number   = previous.sequence_number + 1
 */
export function chainReceipt(
  receipt: UnsignedReceipt,
  previous: SignedReceipt
): UnsignedReceipt {
  const canonical = canonicalize(previous as object);
  if (!canonical) {
    throw new Error("canonicalize returned undefined for previous receipt");
  }

  const prevHash = sha256PrefixedHex(canonical);

  return {
    ...receipt,
    prev_receipt_hash: prevHash,
    sequence_number: previous.sequence_number + 1,
  };
}

/**
 * verifySignature — reconstructs the signing payload from the receipt and
 * verifies the Ed25519 signature against the provided public key.
 */
export async function verifySignature(
  receipt: SignedReceipt,
  publicKey: Uint8Array
): Promise<{ valid: boolean; reason: string }> {
  // Defense-in-depth: reject receipts with missing or invalid signature block
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- runtime null guard for malformed receipts
  if (!(receipt as any).signature) {
    return { valid: false, reason: "missing signature block" };
  }
  if (!isValidKeyId(receipt.signature.key_id)) {
    return { valid: false, reason: `invalid key_id: "${receipt.signature.key_id}"` };
  }

  try {
    const { signature, ...receiptFields } = receipt;

    const payload = buildSigningPayload(receiptFields as ReceiptFields);

    const canonical = canonicalize(payload);
    if (!canonical) {
      return { valid: false, reason: "canonicalize returned undefined" };
    }

    const canonicalBytes = Buffer.from(canonical, "utf8");

    // Decode base64url sig
    const sigBytes = Buffer.from(signature.sig, "base64url");

    const valid = await ed.verifyAsync(sigBytes, canonicalBytes, publicKey);
    return {
      valid,
      reason: valid ? "signature valid" : "signature invalid or failed verification",
    };
  } catch (err) {
    return {
      valid: false,
      reason: `verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * verifyChain — verifies a sequence of receipts:
 * 1. Sorts receipts by sequence_number (handles out-of-order NDJSON)
 * 2. L1: Each receipt's signature is valid (requires publicKey)
 * 3. L2: sequence_number increments by 1, no gaps; prev_receipt_hash matches
 *        SHA-256(JCS(complete previous receipt))
 *
 * Returns { valid, complete, gaps, errors, reason }.
 * complete is true only when workflow_closed is the final receipt.
 * gaps contains sequence_numbers where gaps were detected.
 * errors contains structured ChainError objects for each failure.
 * reason is a human-readable string joining all error messages.
 */
export async function verifyChain(
  receipts: SignedReceipt[],
  publicKey: Uint8Array
): Promise<ChainVerificationResult> {
  if (receipts.length === 0) {
    return { valid: true, complete: false, gaps: [], errors: [], warnings: [], reason: "empty chain" };
  }

  // Sort by sequence_number to handle out-of-order NDJSON files
  const sorted = [...receipts].sort((a, b) => a.sequence_number - b.sequence_number);

  const gaps: number[] = [];
  const errors: ChainError[] = [];
  const warnings: ChainWarning[] = [];

  // F2.4: First receipt must be a workflow_manifest
  if (sorted[0].record_type !== "workflow_manifest") {
    errors.push({
      index: 0,
      sequenceNumber: sorted[0].sequence_number,
      code: "MISSING_MANIFEST",
      message: `receipt[0] record_type="${sorted[0].record_type}": expected workflow_manifest at start of chain`,
    });
  }

  // F2.4: All receipts must share the same workflow_id
  const chainWorkflowId = sorted[0].workflow_id;
  for (let j = 1; j < sorted.length; j++) {
    if (sorted[j].workflow_id !== chainWorkflowId) {
      errors.push({
        index: j,
        sequenceNumber: sorted[j].sequence_number,
        code: "WORKFLOW_ID_MISMATCH",
        message: `receipt[${j}] workflow_id="${sorted[j].workflow_id}": expected "${chainWorkflowId}"`,
      });
    }
  }

  // Build a map of receipt_id → receipt for D2 cross-reference (post_receipt vs action_receipt)
  const receiptById = new Map<string, SignedReceipt>();
  for (const r of sorted) {
    const rid = (r as unknown as Record<string, unknown>).receipt_id as string | undefined;
    if (rid) receiptById.set(rid, r);
  }

  for (let i = 0; i < sorted.length; i++) {
    const current = sorted[i];

    // C3: spec_version must be "var/1.0"
    if (current.spec_version !== "var/1.0") {
      errors.push({
        index: i,
        sequenceNumber: current.sequence_number,
        code: "UNKNOWN_SPEC_VERSION",
        message: `receipt[${i}] spec_version="${current.spec_version}": expected "var/1.0"`,
      });
    }

    // L1: verify signature
    const sigResult = await verifySignature(current, publicKey);
    if (!sigResult.valid) {
      errors.push({
        index: i,
        sequenceNumber: current.sequence_number,
        code: "L1_INVALID",
        message: `receipt[${i}] sequence_number=${current.sequence_number}: L1 signature invalid — ${sigResult.reason}`,
      });
    }

    // L2: sequence_number check
    if (i === 0) {
      // First receipt must be sequence_number 0 (workflow_manifest)
      if (current.sequence_number !== 0) {
        errors.push({
          index: 0,
          sequenceNumber: current.sequence_number,
          code: "SEQUENCE_ERROR",
          message: `receipt[0] sequence_number=${current.sequence_number}: expected 0 for workflow_manifest`,
        });
      }
      if (current.prev_receipt_hash !== null) {
        errors.push({
          index: 0,
          sequenceNumber: current.sequence_number,
          code: "NULL_HASH_EXPECTED",
          message: `receipt[0] prev_receipt_hash must be null for workflow_manifest`,
        });
      }
    } else {
      const previous = sorted[i - 1];

      // Check sequence_number increments by exactly 1
      const expectedSeq = previous.sequence_number + 1;
      if (current.sequence_number !== expectedSeq) {
        // Gap detected
        gaps.push(current.sequence_number);
        errors.push({
          index: i,
          sequenceNumber: current.sequence_number,
          code: "INCOMPLETE_CHAIN",
          message: `INCOMPLETE_CHAIN: sequence gap between ${previous.sequence_number} and ${current.sequence_number} (expected ${expectedSeq})`,
        });
      }

      // Check prev_receipt_hash
      const canonical = canonicalize(previous as object);
      if (!canonical) {
        errors.push({
          index: i - 1,
          sequenceNumber: previous.sequence_number,
          code: "HASH_MISMATCH",
          message: `receipt[${i - 1}] canonicalize returned undefined`,
        });
      } else {
        const expectedHash = sha256PrefixedHex(canonical);
        if (current.prev_receipt_hash !== expectedHash) {
          errors.push({
            index: i,
            sequenceNumber: current.sequence_number,
            code: "HASH_MISMATCH",
            message: `receipt[${i}] prev_receipt_hash mismatch: got ${current.prev_receipt_hash}, expected ${expectedHash}`,
          });
        }
      }
    }

    // D1: DEGRADED_STATE warning — action_receipt with billable_reason=DEGRADED_SESSION
    if (current.record_type === "action_receipt") {
      const ar = current as unknown as Record<string, unknown>;
      if (ar.billable_reason === "DEGRADED_SESSION") {
        warnings.push({
          index: i,
          sequenceNumber: current.sequence_number,
          code: "DEGRADED_STATE",
          message: `receipt[${i}] action_receipt has billable_reason=DEGRADED_SESSION — session operated in degraded state`,
        });
      }
    }

    // D2: MONEY_ACTION_TAG_MISSING warning — post_receipt exists but action_receipt lacks money_action=true
    if (current.record_type === "post_receipt") {
      const pr = current as unknown as Record<string, unknown>;
      const preReceiptId = pr.pre_receipt_id as string | undefined;
      if (preReceiptId) {
        const actionReceipt = receiptById.get(preReceiptId);
        if (actionReceipt) {
          const ar = actionReceipt as unknown as Record<string, unknown>;
          if (!ar.money_action) {
            warnings.push({
              index: i,
              sequenceNumber: current.sequence_number,
              code: "MONEY_ACTION_TAG_MISSING",
              message: `receipt[${i}] post_receipt references action_receipt (${preReceiptId}) that lacks money_action=true`,
            });
          }
        }
      }
    }
  }

  // complete: true only when workflow_closed is the last receipt in the sorted chain
  const lastReceipt = sorted[sorted.length - 1];
  const complete = lastReceipt.record_type === "workflow_closed";

  if (errors.length > 0) {
    return { valid: false, complete, gaps, errors, warnings, reason: errors.map((e) => e.message).join("; ") };
  }

  return { valid: true, complete, gaps: [], errors: [], warnings, reason: "chain valid" };
}

// ── L3: RFC 3161 sidecar verification ────────────────────────────────────────

const DEFAULT_ACCEPTING_TSA_IDS = ["digicert", "sectigo", "globalsign"];

/**
 * Load a .tsa sidecar file (one TsaRecord per NDJSON line).
 * Returns [] if the file does not exist.
 */
export function loadTsaSidecar(tsaFilePath: string): TsaRecord[] {
  if (!fs.existsSync(tsaFilePath)) return [];
  const content = fs.readFileSync(tsaFilePath, "utf8");
  return content
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as TsaRecord);
}

/**
 * L3 verification — checks RFC 3161 timestamp records against receipts.
 *
 * Per receipt:
 *   - No sidecar entry → SKIPPED (not a failure)
 *   - Entry present, tsa_id NOT in accepting_tsa_ids → FAIL "tsa_not_in_allowlist"
 *   - Entry present, rfc3161_token not parseable as DER → FAIL "tsa_der_parse_error"
 *   - Entry present, PKIStatus != granted → FAIL "tsa_pkistatus_not_granted"
 *   - Entry present, messageImprint.hashedMessage != SHA-256(JCS(receipt)) → FAIL "tsa_messageimprint_mismatch"
 *   - Entry present, all checks pass → PASS
 *
 * Overall:
 *   - Any FAIL → FAIL (with failed_receipt_id)
 *   - All SKIPPED → SKIPPED
 *   - At least one PASS, no FAILs → PASS
 */
export async function verifyL3(
  receipts: SignedReceipt[],
  tsaRecords: TsaRecord[],
  options?: { accepting_tsa_ids?: string[] }
): Promise<L3Result> {
  if (receipts.length === 0) return { status: "SKIPPED" };

  const acceptingTsaIds = options?.accepting_tsa_ids ?? DEFAULT_ACCEPTING_TSA_IDS;
  const recordById = new Map(tsaRecords.map((r) => [r.receipt_id, r]));

  let anyPass = false;

  for (const receipt of receipts) {
    // Batch timestamping (v1.1) — this branch never fires in v1.0 because
    // no receipts have batch_id and no sidecar entries have entry_type: "batch".
    // UNREACHABLE in v1.0: none of the SignedReceipt subtypes (WorkflowManifestFields,
    // ActionReceiptFields, WorkflowClosedFields) carry a batch_id field; the double-cast
    // to unknown then Record<string, unknown> is an intentional forward-compatibility probe.
    const receiptBatchId = (receipt as unknown as Record<string, unknown>).batch_id;
    if (receiptBatchId) {
      const batchEntry = tsaRecords.find(
        (r) =>
          (r as unknown as Record<string, unknown>).entry_type === "batch" &&
          (r as unknown as Record<string, unknown>).batch_id === receiptBatchId
      );
      if (batchEntry) {
        // v1.1: verify merkle_root RFC 3161 token + inclusion proof
        // v1.0: placeholder — returns PENDING, implementation deferred
        return { status: "PENDING" as const };
      }
    }

    // New receipt types (post_receipt, recovery_event, budget_warning, reservation_expired)
    // use type-specific ID fields (post_receipt_id, etc.) rather than receipt_id.
    // Access receipt_id dynamically; new types without receipt_id are SKIPPED in L3.
    const primaryId = (receipt as unknown as Record<string, unknown>).receipt_id as string | undefined;
    if (!primaryId) continue; // SKIPPED for new receipt types without receipt_id

    const tsaRecord = recordById.get(primaryId);
    if (!tsaRecord) continue; // SKIPPED for this receipt

    // [1] TSA allowlist check
    if (!acceptingTsaIds.includes(tsaRecord.tsa_id)) {
      return {
        status: "FAIL",
        reason: `tsa_not_in_allowlist`,
        failed_receipt_id: primaryId,
      };
    }

    // [2] Base64-decode and parse the DER token
    let tsResp: TimeStampResp;
    try {
      const derBytes = Buffer.from(tsaRecord.rfc3161_token, "base64");
      // Ensure proper ArrayBuffer (Buffer shares backing store with offset)
      const derBuf = derBytes.buffer.slice(
        derBytes.byteOffset,
        derBytes.byteOffset + derBytes.byteLength
      );
      tsResp = AsnConvert.parse(derBuf as ArrayBuffer, TimeStampResp);
    } catch {
      return {
        status: "FAIL",
        reason: "tsa_der_parse_error",
        failed_receipt_id: primaryId,
      };
    }

    // [3] PKIStatus must be granted (0) or grantedWithMods (1)
    if (
      tsResp.status.status !== PKIStatus.granted &&
      tsResp.status.status !== PKIStatus.grantedWithMods
    ) {
      return {
        status: "FAIL",
        reason: "tsa_pkistatus_not_granted",
        failed_receipt_id: primaryId,
      };
    }

    // [4] timeStampToken must be present when status = granted
    if (!tsResp.timeStampToken) {
      return {
        status: "FAIL",
        reason: "tsa_der_parse_error",
        failed_receipt_id: primaryId,
      };
    }

    // [5] Navigate: timeStampToken.content → SignedData → encapContentInfo → TSTInfo
    let tstInfo: TSTInfo;
    try {
      const signedData = AsnConvert.parse(
        tsResp.timeStampToken.content as ArrayBuffer,
        SignedData
      );
      const eContent = signedData.encapContentInfo.eContent;
      if (!eContent) throw new Error("no eContent");

      // eContent.single is an OctetString (Uint8Array) containing TSTInfo DER bytes
      const tstBytes = eContent.single
        ? eContent.single.buffer.slice(
            eContent.single.byteOffset,
            eContent.single.byteOffset + eContent.single.byteLength
          )
        : eContent.any;
      if (!tstBytes) throw new Error("no tstBytes");

      tstInfo = AsnConvert.parse(tstBytes as ArrayBuffer, TSTInfo);
    } catch {
      return {
        status: "FAIL",
        reason: "tsa_der_parse_error",
        failed_receipt_id: primaryId,
      };
    }

    // [5a] C1: OID must be SHA-256 — reject tokens using weaker hash algorithms
    const SHA256_OID_EXPECTED = "2.16.840.1.101.3.4.2.1";
    const actualOid = tstInfo.messageImprint.hashAlgorithm.algorithm;
    if (actualOid !== SHA256_OID_EXPECTED) {
      return {
        status: "FAIL",
        reason: "tsa_hash_algorithm_not_sha256",
        failed_receipt_id: primaryId,
      };
    }

    // [5b] C2: genTime must be >= receipt.issued_at (backdated timestamps are invalid)
    const issuedAtStr = (receipt as unknown as Record<string, unknown>).issued_at as string | undefined;
    if (issuedAtStr) {
      const issuedAtMs = new Date(issuedAtStr).getTime();
      const genTimeMs = tstInfo.genTime.getTime();
      if (isNaN(issuedAtMs) || isNaN(genTimeMs)) {
        return {
          status: "FAIL",
          reason: "tsa_gentime_parse_error",
          failed_receipt_id: primaryId,
        };
      }
      if (genTimeMs < issuedAtMs) {
        return {
          status: "FAIL",
          reason: "tsa_gentime_before_issued_at",
          failed_receipt_id: primaryId,
        };
      }
    }

    // [6] Compute SHA-256(JCS(complete signed receipt)) and compare
    const canonical = canonicalize(receipt as object);
    if (!canonical) {
      return {
        status: "FAIL",
        reason: "tsa_der_parse_error",
        failed_receipt_id: primaryId,
      };
    }
    const expectedHash = createHash("sha256").update(canonical).digest();

    // hashedMessage is an OctetString (Uint8Array)
    const actualHash = new Uint8Array(
      tstInfo.messageImprint.hashedMessage.buffer.slice(
        tstInfo.messageImprint.hashedMessage.byteOffset,
        tstInfo.messageImprint.hashedMessage.byteOffset +
          tstInfo.messageImprint.hashedMessage.byteLength
      )
    );

    const match =
      expectedHash.length === actualHash.length &&
      expectedHash.every((b, i) => b === actualHash[i]);

    if (!match) {
      return {
        status: "FAIL",
        reason: "tsa_messageimprint_mismatch",
        failed_receipt_id: primaryId,
      };
    }

    anyPass = true;
  }

  return anyPass ? { status: "PASS" } : { status: "SKIPPED" };
}

// ── L4: Outcome Binding verification ─────────────────────────────────────────

/**
 * L4 — Outcome Binding verification (VAR Core v1.0 §2.4).
 *
 * Checks structural invariants for money action receipts:
 * - RI-1: Every ALLOW'd money action has exactly one terminal post_receipt
 * - RI-7: No duplicate idempotency keys for terminal SUCCESS outcomes
 * - Budget warnings are reported as WARN (not FAIL)
 *
 * Returns L4: N/A when no money actions are present.
 * Returns L4: FAIL when a critical invariant is violated.
 * Returns L4: WARN when non-critical anomalies are present.
 * Returns L4: PASS when all checks pass and money actions are present.
 */
export async function verifyL4(
  receipts: SignedReceipt[],
  // reserved for future use (policy, projection options)
  _options?: Record<string, unknown>
): Promise<L4Result> {
  const violations: L4Violation[] = [];

  // Track money-action ALLOW'd action_receipt IDs and their tool names
  const moneyActionAllowIds: string[] = [];
  const moneyActionAllowTools = new Map<string, string>(); // receipt_id → tool_name

  // Track pre_receipt_ids that have a corresponding post_receipt
  const resolvedPreIds = new Set<string>();

  // Track dedupe keys for duplicate SUCCESS detection
  const successDedupeKeys = new Map<string, string>(); // dedupe_key → post_receipt_id

  for (const r of receipts) {
    const rr = r as unknown as Record<string, unknown>;

    if (r.record_type === "action_receipt") {
      if (rr["money_action"] === true && rr["decision"] === "ALLOW") {
        const receiptId = rr["receipt_id"] as string | undefined;
        if (receiptId) {
          moneyActionAllowIds.push(receiptId);
          moneyActionAllowTools.set(receiptId, (rr["tool_name"] as string) ?? "unknown");
        }
      }
    }

    if (r.record_type === "post_receipt") {
      const preReceiptId = rr["pre_receipt_id"] as string | undefined;
      if (preReceiptId) {
        resolvedPreIds.add(preReceiptId);
      }

      // RI-7: duplicate idempotency key check for terminal SUCCESS outcomes
      const idempotencyKey = rr["idempotency_key"] as string | null;
      const terminalOutcome = rr["terminal_outcome"] as string | undefined;
      if (idempotencyKey && terminalOutcome === "SUCCESS") {
        const toolName = (rr["tool_name"] as string) ?? "";
        const accountContext = (rr["account_context"] as string | null) ?? "";
        const dedupeKey = `${toolName}:money_action:${idempotencyKey}:${accountContext}`;
        const existingId = successDedupeKeys.get(dedupeKey);
        if (existingId) {
          violations.push({
            code: "DUPLICATE_IDEMPOTENCY_KEY",
            message: `Duplicate idempotency key "${idempotencyKey}" for tool "${toolName}" — second terminal SUCCESS post_receipt`,
            receiptId: (rr["post_receipt_id"] as string | undefined),
          });
        } else {
          successDedupeKeys.set(dedupeKey, (rr["post_receipt_id"] as string) ?? "");
        }
      }
    }

    if (r.record_type === "budget_warning") {
      const thresholdPct = rr["threshold_pct"] as number;
      const budgetWarningId = rr["budget_warning_id"] as string | undefined;
      violations.push({
        code: thresholdPct >= 100 ? "BUDGET_CAP_ENFORCED" : "BUDGET_WARNING",
        message: thresholdPct >= 100
          ? `Budget cap enforced (${thresholdPct}% of max_spend reached)`
          : `Budget warning at ${thresholdPct}% of max_spend`,
        receiptId: budgetWarningId,
      });
    }
  }

  // N/A: no money actions and no budget violations
  if (moneyActionAllowIds.length === 0 && violations.length === 0) {
    return { status: "N/A", violations: [] };
  }

  // RI-1: check for missing post_receipts
  for (const receiptId of moneyActionAllowIds) {
    if (!resolvedPreIds.has(receiptId)) {
      const toolName = moneyActionAllowTools.get(receiptId) ?? "unknown";
      violations.push({
        code: "MISSING_POST_RECEIPT",
        message: `Money action "${toolName}" (receipt_id=${receiptId}) has no terminal post_receipt`,
        receiptId,
      });
    }
  }

  const FAIL_CODES: L4ViolationCode[] = [
    "MISSING_POST_RECEIPT",
    "PROJECTION_HASH_MISMATCH",
    "PROJECTION_UNRESOLVABLE",
    "PROJECTION_UNKNOWN_OPERATION",
  ];

  const hasFail = violations.some((v) => FAIL_CODES.includes(v.code));
  const hasWarn = violations.some((v) => !FAIL_CODES.includes(v.code));

  if (hasFail) return { status: "FAIL", violations };
  if (hasWarn) return { status: "WARN", violations };
  return { status: "PASS", violations };
}

// ── DER introspection utility ─────────────────────────────────────────────────

/**
 * Parse an RFC 3161 TimeStampResp DER token and return the hex-encoded bytes
 * of messageImprint.hashedMessage — the hash the TSA attested to.
 *
 * Used by the conform runner (TV-16) to verify that @peculiar/asn1-* DER
 * parsing returns the expected hash bytes, independently of verifyL3.
 * Returns null when the token cannot be parsed.
 */
export async function parseMessageImprintHex(
  tsaTokenBase64: string
): Promise<string | null> {
  try {
    const derBytes = Buffer.from(tsaTokenBase64, "base64");
    const derBuf = derBytes.buffer.slice(
      derBytes.byteOffset,
      derBytes.byteOffset + derBytes.byteLength
    );
    const tsResp = AsnConvert.parse(derBuf as ArrayBuffer, TimeStampResp);
    if (!tsResp.timeStampToken) return null;

    const signedData = AsnConvert.parse(
      tsResp.timeStampToken.content as ArrayBuffer,
      SignedData
    );
    const eContent = signedData.encapContentInfo.eContent;
    if (!eContent) return null;

    const tstBytes = eContent.single
      ? eContent.single.buffer.slice(
          eContent.single.byteOffset,
          eContent.single.byteOffset + eContent.single.byteLength
        )
      : eContent.any;
    if (!tstBytes) return null;

    const tstInfo = AsnConvert.parse(tstBytes as ArrayBuffer, TSTInfo);
    const hashBytes = new Uint8Array(
      tstInfo.messageImprint.hashedMessage.buffer.slice(
        tstInfo.messageImprint.hashedMessage.byteOffset,
        tstInfo.messageImprint.hashedMessage.byteOffset +
          tstInfo.messageImprint.hashedMessage.byteLength
      )
    );
    return Buffer.from(hashBytes).toString("hex");
  } catch {
    return null;
  }
}
