// @varcore/store — public types

export interface ReceiptRow {
  receipt_id: string;
  workflow_id: string;
  record_type: string;
  sequence_number: number;
  agent_id: string;
  issued_at: string;
  tool_name: string | null;
  decision: string | null;
  decision_reason: string | null;
  blast_radius: string | null;
  reversible: number | null;       // 0 | 1 (SQLite boolean)
  params_canonical_hash: string | null;
  policy_bundle_hash: string;
  queue_status: string | null;
  failure_reason: string | null;
  prev_receipt_hash: string | null;
  sig: string;
  key_id: string;
  l1_status: string;               // "PASS" | "FAIL"
  l2_status: string;               // "PASS" | "FAIL"
  l3_status: string;               // "PASS" | "FAIL" | "SKIPPED"
  source_file: string;
}

export interface WorkflowRow {
  workflow_id: string;
  agent_id: string;
  workflow_id_source: string;
  initiated_at: string;
  closed_at: string | null;
  total_calls: number | null;
  total_blocked: number | null;
  session_duration_ms: number | null;
  close_reason: string | null;
  complete: number;                // 0 | 1 (SQLite boolean)
  source_file: string;
}

export interface TsaTokenRow {
  receipt_id: string;
  rfc3161_token: string;
  tsa_id: string;
  timestamped_at: string;
}

export interface ReceiptQuery {
  workflow_id?: string;
  agent_id?: string;
  tool_name?: string;
  decision?: string;
  from?: string;         // ISO date — inclusive lower bound on issued_at
  to?: string;           // ISO date — inclusive upper bound on issued_at
  record_type?: string;
  limit?: number;        // default 100
  offset?: number;       // default 0
}

export interface WorkflowSummary {
  workflow_id: string;
  agent_id: string;
  initiated_at: string;
  closed_at: string | null;
  total_calls: number | null;
  total_blocked: number | null;
  session_duration_ms: number | null;
  close_reason: string | null;
  complete: boolean;
}

/**
 * ReportRenderer — the open interface that the enterprise package implements.
 * PlainTextReportRenderer is the open-source default (no PDF generation).
 * The enterprise PDF renderer implements this interface without changing the CLI contract.
 */
export interface ReportRenderer {
  render(
    workflows: WorkflowSummary[],
    receipts: Map<string, ReceiptRow[]>
  ): Promise<void>;
  /** File extension for the output (e.g. "txt", "pdf") */
  readonly extension: string;
}
