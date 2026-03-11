// VAR v1.0 — all types derived from Section 3 of the Public Contract

/**
 * Validate that a key_id is safe for file-system and URL use.
 * Accepts only alphanumeric characters, hyphens, and underscores (1–64 chars).
 * Rejects path-traversal sequences, slashes, dots, and other special characters.
 */
export function isValidKeyId(id: string): boolean {
  return /^[a-zA-Z0-9_-]{1,64}$/.test(id);
}

// ── VAR-Money v1.0 / Walk mode enumerations ───────────────────────────────────

/** Deployment mode (docs/spec/var-core-v1.0.md §1.1). Run is reserved for v1.1. */
export type DeploymentMode = "crawl" | "walk" | "run";

/** Taxonomy manifest load status at session start. */
export type TaxonomyStatus = "OK" | "CACHED" | "UNAVAILABLE";

/** Why an action_receipt is or is not billable (VAR-Money v1.0 §6). */
export type BillableReason =
  | "MONEY_ACTION_ATTEMPT"
  | "PROXY_GUARD"
  | "DEGRADED_SESSION"
  | "SIMULATION"
  | "READ_ONLY"
  | "INTERNAL";

/** Terminal outcome for a money action post_receipt (docs/reference/receipt-types.md). */
export type TerminalOutcome =
  | "SUCCESS"
  | "DENIED"
  | "ESCALATED"
  | "TIMEOUT"
  | "ERROR"
  | "CANCELED";

/** Open-pre journal integrity status after proxy restart. */
export type IndexStatus = "OK" | "CORRUPT";

/** Recovery method used during startup integrity check. */
export type RecoveryMethod = "INDEX" | "CHECKPOINT";

/** Why a budget reservation was released. */
export type ReservationReason = "TTL_EXPIRY" | "MANUAL_RELEASE";

export type RecordType =
  | "workflow_manifest"
  | "action_receipt"
  | "workflow_closed"
  | "post_receipt"
  | "recovery_event"
  | "budget_warning"
  | "reservation_expired"
  | "approval_receipt";

/** Terminal outcome of a STEP_UP approval request. */
export type ApprovalOutcome = "APPROVED" | "DENIED" | "TIMEOUT";

export type WorkflowIdSource = "nonsudo_generated" | "framework_mapped" | "parent_join";

export type Decision = "ALLOW" | "BLOCK" | "FAIL_OPEN" | "FAIL_CLOSED" | "STEP_UP";

export type QueueStatus = "COMPLETED" | "DEAD_LETTER";

export type BlastRadius = "LOW" | "MED" | "HIGH" | "CRITICAL";

export type FallbackPolicy = "fail_closed" | "fail_open";

export type CloseReason = "connection_teardown" | "ttl_expired" | "explicit_close";

// Section 4: Signature block
export interface SignatureBlock {
  alg: "Ed25519";
  key_id: string;
  sig: string; // base64url
}

// Section 3.1: Fields on ALL receipt types
interface BaseReceiptFields {
  receipt_id: string;           // ULID
  record_type: RecordType;
  spec_version: "var/1.0";
  workflow_id: string;
  workflow_id_source: WorkflowIdSource;
  agent_id: string;
  issued_at: string;            // RFC3339
  prev_receipt_hash: string | null; // sha256:<hex> or null
  sequence_number: number;
  policy_bundle_hash: string;   // sha256:<hex>
  rfc3161_token: string | null; // null in Phase 0
  tsa_id: string | null;        // null in Phase 0
}

// Section 3.2: action_receipt-only fields
export interface ActionReceiptFields extends BaseReceiptFields {
  record_type: "action_receipt";
  tool_name: string;
  params_canonical_hash: string; // sha256:<hex>
  decision: Decision;
  decision_reason: string;
  decision_order: number;
  queue_status: QueueStatus;
  queue_timeout_ms: number;
  blast_radius: BlastRadius;
  reversible: boolean;
  state_version_before: number;
  state_version_after: number;
  response_hash: string | null; // always null at signing time in v0.1
  /**
   * Whether the upstream tool server was called before this receipt was written.
   * true  — upstream was called (completed or timed out before response).
   * false — upstream was NOT called (proxy-guard BLOCK: params_too_large, undeclared_tool,
   *          declared_tools_unavailable) or VCB DEAD_LETTER.
   * null  — regular COMPLETED receipt (ALLOW, policy BLOCK, STEP_UP, FAIL_OPEN);
   *          upstream call status is not separately tracked for these outcomes.
   * Absent on receipts written by test utilities that do not exercise the upstream path.
   */
  upstream_call_initiated?: boolean | null;
  // ── VAR-Money v1.0 / Session A new signed fields ──────────────────────────
  /** Whether this action is a money action per VAR-Money v1.0 §2. */
  money_action?: boolean;
  /** Amount in minor units from the validated request parameter. Null for non-money actions. */
  amount_minor_units?: number | null;
  /** Whether this action is billable per VAR-Money v1.0 §6. */
  billable?: boolean;
  /** Human-readable reason for billability classification. */
  billable_reason?: BillableReason;
  /**
   * ULID of the approval_receipt that resolved this STEP_UP decision.
   * Set only when the approval engine is active and a STEP_UP decision is pending.
   * Null for non-STEP_UP actions.
   */
  pending_approval_id?: string | null;
}

// Section 3.3: Additional fields on action_receipt when queue_status is DEAD_LETTER
export interface DeadLetterActionReceiptFields extends ActionReceiptFields {
  queue_status: "DEAD_LETTER";
  failure_reason: string;
  fallback_policy: FallbackPolicy;
}

// Section 3.4: workflow_manifest-only fields
export interface WorkflowManifestFields extends BaseReceiptFields {
  record_type: "workflow_manifest";
  initiator_id: string;
  workflow_owner: string;
  session_budget: Record<string, number>;
  declared_tools: string[];
  capability_manifest_hash: string | null; // sha256:<hex> or null
  parent_workflow_id: string | null;
  framework_ref: string | null;
  /**
   * Set to true when the proxy's tools/list fetch failed at session creation.
   * Makes the infrastructure failure visible in the audit trail.
   * Absent (undefined) when the fetch succeeded or returned empty.
   */
  declared_tools_fetch_failed?: boolean;
  // ── VAR-Money v1.0 / Session A new signed fields ──────────────────────────
  /** Deployment mode active for this session. Defaults to "walk". */
  mode?: DeploymentMode;
  /** Status of the VAR-Money taxonomy manifest at session start. */
  taxonomy_status?: TaxonomyStatus;
  /** Tool names explicitly overridden via unsafe_override: true in policy. */
  money_action_overrides?: string[];
}

// Section 3.5: workflow_closed-only fields (Phase 1)
export interface WorkflowClosedFields extends BaseReceiptFields {
  record_type: "workflow_closed";
  total_calls: number;
  total_blocked: number;
  total_spend: number | null;
  session_duration_ms: number;
  close_reason: CloseReason;
}

// ── New receipt types: VAR-Money v1.0 / Walk mode (Session A) ─────────────────
//
// These types do NOT extend BaseReceiptFields because they use type-specific
// primary IDs (post_receipt_id, recovery_event_id, etc.) per the spec in
// docs/reference/receipt-types.md.

/**
 * post_receipt — emitted once per ALLOW'd money action with the terminal outcome.
 * Chain position: immediately after the corresponding action_receipt.
 *
 * D-1 deviation (Session A): account_context field added (not in spec doc) for
 * RI-7 idempotency deduplication scope. Signed.
 */
export interface PostReceiptFields {
  post_receipt_id: string;          // ULID — unique ID for this post-receipt
  record_type: "post_receipt";
  spec_version: "var/1.0";
  pre_receipt_id: string;           // ULID — receipt_id of the corresponding action_receipt
  workflow_id: string;
  agent_id: string;
  sequence_number: number;
  prev_receipt_hash: string;        // sha256:hex — always non-null (never first receipt)
  policy_bundle_hash: string;
  tool_name: string;
  terminal_outcome: TerminalOutcome;
  upstream_response_digest: string | null;  // sha256:hex; null on TIMEOUT/ERROR/CANCELED
  projection_id: string | null;
  projection_hash: string | null;
  idempotency_key: string | null;
  tool_call_correlation_id: string | null;
  execution_start_ms: number;       // monotonic ms when upstream call was initiated
  execution_end_ms: number;         // monotonic ms when upstream call terminated
  degraded_reason: string | null;
  billable: boolean;
  billable_reason: BillableReason;
  issued_at: string;                // ISO 8601
  /** D-1 Session A: account_context for RI-7 idempotency deduplication scope. Signed. */
  account_context: string | null;
  rfc3161_token: string | null;     // NOT signed; populated by TSA worker
  tsa_id: string | null;            // NOT signed; populated by TSA worker
}

/**
 * recovery_event — emitted as the first receipt after a proxy restart.
 * Records integrity check results on the open-pre index.
 * Implements RI-10 from docs/spec/var-core-v1.0.md §3.
 */
export interface RecoveryEventFields {
  recovery_event_id: string;        // ULID
  record_type: "recovery_event";
  spec_version: "var/1.0";
  workflow_id: string;
  agent_id: string;
  sequence_number: number;
  prev_receipt_hash: string;        // sha256:hex
  policy_bundle_hash: string;
  recovered_open_pres_count: number;
  index_status: IndexStatus;
  recovery_method: RecoveryMethod;
  scan_window_minutes: number | null;    // always null — bounded scan removed in v1.0
  scan_receipts_examined: number | null; // always null — bounded scan removed in v1.0
  issued_at: string;                // ISO 8601
  rfc3161_token: string | null;     // NOT signed
  tsa_id: string | null;            // NOT signed
}

/**
 * budget_warning — emitted when cumulative spend crosses 90% or 100% of max_spend.
 * VAR-Money v1.0 §3.5.
 */
export interface BudgetWarningFields {
  budget_warning_id: string;        // ULID
  record_type: "budget_warning";
  spec_version: "var/1.0";
  workflow_id: string;
  agent_id: string;
  sequence_number: number;
  prev_receipt_hash: string;        // sha256:hex
  policy_bundle_hash: string;
  tool_name: string;
  spent: number;                    // minor units
  reserved: number;                 // minor units
  cap: number;                      // minor units (max_spend)
  threshold_pct: 90 | 100;
  issued_at: string;                // ISO 8601
  rfc3161_token: string | null;     // NOT signed
  tsa_id: string | null;            // NOT signed
}

/**
 * reservation_expired — emitted when a TIMEOUT-held reservation reaches its TTL.
 * VAR-Money v1.0 §3.3 and RI-6 from docs/spec/var-core-v1.0.md §3.
 */
export interface ReservationExpiredFields {
  reservation_expired_id: string;   // ULID
  record_type: "reservation_expired";
  spec_version: "var/1.0";
  workflow_id: string;
  agent_id: string;
  sequence_number: number;
  prev_receipt_hash: string;        // sha256:hex
  policy_bundle_hash: string;
  pre_receipt_id: string;           // action_receipt that initiated the reservation
  amount_released: number;          // minor units
  currency: string;                 // ISO 4217
  reason: ReservationReason;
  issued_at: string;                // ISO 8601
  rfc3161_token: string | null;     // NOT signed
  tsa_id: string | null;            // NOT signed
}

/**
 * approval_receipt — emitted when a STEP_UP decision triggers the approval engine.
 * Chain position: immediately after the corresponding action_receipt.
 * VAR-Money v1.0 §3.4 (Group 3 — STEP_UP approval engine).
 */
export interface ApprovalReceiptFields extends BaseReceiptFields {
  record_type: "approval_receipt";
  /** receipt_id of the action_receipt that triggered this approval flow. */
  action_receipt_id: string;
  /** ULID — unique ID for this approval receipt. */
  approval_receipt_id: string;
  /** Tool name for cross-reference. */
  tool_name: string;
  /** Final outcome of the approval request. */
  approval_outcome: ApprovalOutcome;
  /** Who approved/denied the request (from approve/deny file content), or null. */
  approver: string | null;
  /** Directory where approval files are polled. */
  approval_dir: string;
  /** How long we waited before the decision or timeout (ms). */
  wait_duration_ms: number;
}

// Union type for all receipt field sets
export type ReceiptFields =
  | WorkflowManifestFields
  | ActionReceiptFields
  | DeadLetterActionReceiptFields
  | WorkflowClosedFields
  | PostReceiptFields
  | RecoveryEventFields
  | BudgetWarningFields
  | ReservationExpiredFields
  | ApprovalReceiptFields;

// UnsignedReceipt is the receipt with all fields but no signature
export type UnsignedReceipt = ReceiptFields;

// Named signed receipt subtypes — preserve the discriminant for TypeScript narrowing
export type SignedWorkflowManifest = WorkflowManifestFields & { signature: SignatureBlock };
export type SignedActionReceipt = ActionReceiptFields & { signature: SignatureBlock };
export type SignedDeadLetterReceipt = DeadLetterActionReceiptFields & { signature: SignatureBlock };
export type SignedWorkflowClosed = WorkflowClosedFields & { signature: SignatureBlock };
export type SignedPostReceipt = PostReceiptFields & { signature: SignatureBlock };
export type SignedRecoveryEvent = RecoveryEventFields & { signature: SignatureBlock };
export type SignedBudgetWarning = BudgetWarningFields & { signature: SignatureBlock };
export type SignedReservationExpired = ReservationExpiredFields & { signature: SignatureBlock };
export type SignedApprovalReceipt = ApprovalReceiptFields & { signature: SignatureBlock };

// SignedReceipt is a union of all named signed subtypes
export type SignedReceipt =
  | SignedWorkflowManifest
  | SignedActionReceipt
  | SignedDeadLetterReceipt
  | SignedWorkflowClosed
  | SignedPostReceipt
  | SignedRecoveryEvent
  | SignedBudgetWarning
  | SignedReservationExpired
  | SignedApprovalReceipt;

// ── Chain verification result ─────────────────────────────────────────────────

export interface ChainVerificationResult {
  valid: boolean;
  /** true only when workflow_closed is the final receipt in the chain. */
  complete: boolean;
  gaps: number[];
  errors: ChainError[];
  /** Informational anomalies — do NOT affect valid. D1/D2 checks. */
  warnings: ChainWarning[];
  reason?: string;
}

// Chain error types — structured errors from verifyChain
export type ChainErrorCode =
  | "L1_INVALID"
  | "INCOMPLETE_CHAIN"
  | "HASH_MISMATCH"
  | "SEQUENCE_ERROR"
  | "NULL_HASH_EXPECTED"
  | "MISSING_MANIFEST"
  | "WORKFLOW_ID_MISMATCH"
  | "UNKNOWN_SPEC_VERSION"; // C3: receipt has an unrecognised spec_version value

export interface ChainError {
  index: number;           // receipt array index (-1 if not attributable to a specific receipt)
  sequenceNumber: number;  // receipt.sequence_number at that index
  code: ChainErrorCode;
  message: string;
}

// Chain warning codes — informational anomalies that do NOT invalidate the chain
export type ChainWarningCode =
  | "DEGRADED_STATE"           // D1: receipt(s) have billable_reason=DEGRADED_SESSION
  | "MONEY_ACTION_TAG_MISSING"; // D2: post_receipt present but action_receipt lacks money_action=true

export interface ChainWarning {
  index: number;           // receipt array index (-1 if chain-level warning)
  sequenceNumber: number;
  code: ChainWarningCode;
  message: string;
}

// ── L3: RFC 3161 Timestamping ─────────────────────────────────────────────────

/** One record in the .tsa sidecar file (one per signed receipt). */
export interface TsaRecord {
  receipt_id: string;
  rfc3161_token: string;  // base64-encoded DER TimeStampResp
  tsa_id: string;         // provider name (e.g. "digicert")
  timestamped_at: string; // RFC3339
}

export type L3Status = "PASS" | "FAIL" | "SKIPPED" | "PENDING";

export interface L3Result {
  status: L3Status;
  reason?: string;
  failed_receipt_id?: string;
}

// ── L4: Outcome Binding (VAR Core v1.0 §2.4) ─────────────────────────────────

export type L4Status = "PASS" | "FAIL" | "WARN" | "N/A";

export type L4ViolationCode =
  | "MISSING_POST_RECEIPT"
  | "PROJECTION_HASH_MISMATCH"
  | "PROJECTION_UNRESOLVABLE"
  | "PROJECTION_UNKNOWN_OPERATION"
  | "BUDGET_WARNING"
  | "BUDGET_CAP_ENFORCED"
  | "DUPLICATE_IDEMPOTENCY_KEY";

export interface L4Violation {
  code: L4ViolationCode;
  message: string;
  receiptId?: string;
}

export interface L4Result {
  status: L4Status;
  violations: L4Violation[];
}
