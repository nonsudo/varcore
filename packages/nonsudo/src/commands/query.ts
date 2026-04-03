/**
 * nonsudo query [options]
 *
 * Queries the receipt store with optional filters. Output formats: table (default),
 * json, csv. When --workflow-id is specified, prepends a workflow summary header.
 */

import * as os from "os";
import * as path from "path";
import { ReceiptStore, ReceiptRow, WorkflowSummary } from "@varcore/store";

const DEFAULT_DB = path.join(os.homedir(), ".nonsudo", "receipts.db");

// ── Formatting ────────────────────────────────────────────────────────────────

function truncate(s: string, len: number): string {
  return s.length > len ? s.slice(0, len) : s;
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function formatWorkflowHeader(wf: WorkflowSummary): string {
  const durationStr = wf.session_duration_ms != null
    ? `${wf.session_duration_ms.toLocaleString()}ms`
    : "—";
  const callsStr = wf.total_calls != null ? String(wf.total_calls) : "—";
  const blockedStr = wf.total_blocked != null ? String(wf.total_blocked) : "—";
  const closeInfo = wf.closed_at
    ? `${wf.closed_at}${wf.close_reason ? ` (${wf.close_reason})` : ""}`
    : "open";

  return [
    `Workflow: ${wf.workflow_id}`,
    `  Agent:    ${wf.agent_id}`,
    `  Started:  ${wf.initiated_at}`,
    `  Closed:   ${closeInfo}`,
    `  Duration: ${durationStr} · Calls: ${callsStr} · Blocked: ${blockedStr} · Complete: ${wf.complete ? "yes" : "no"}`,
    "",
  ].join("\n");
}

function formatReceiptsTable(rows: ReceiptRow[], withWorkflowId: boolean): string {
  const lines: string[] = [];

  if (!withWorkflowId) {
    lines.push(
      `  ${pad("receipt_id", 10)}  ${pad("workflow_id", 10)}  ${pad("seq", 4)}  ${pad("tool_name", 18)}  ${pad("decision", 10)}  ${pad("issued_at", 20)}  ${pad("L1", 6)}  ${pad("L2", 6)}  ${pad("L3", 6)}`
    );
    lines.push(
      `  ${pad("─".repeat(10), 10)}  ${pad("─".repeat(10), 10)}  ${pad("───", 4)}  ${pad("─".repeat(18), 18)}  ${pad("─".repeat(10), 10)}  ${pad("─".repeat(20), 20)}  ${pad("──────", 6)}  ${pad("──────", 6)}  ${pad("──────", 6)}`
    );
    for (const r of rows) {
      lines.push(
        `  ${pad(truncate(r.receipt_id, 10), 10)}  ${pad(truncate(r.workflow_id, 10), 10)}  ${pad(String(r.sequence_number), 4)}  ${pad(r.tool_name ?? "—", 18)}  ${pad(r.decision ?? "—", 10)}  ${pad(r.issued_at, 20)}  ${pad(r.l1_status, 6)}  ${pad(r.l2_status.split(":")[0], 6)}  ${pad(r.l3_status, 6)}`
      );
    }
  } else {
    lines.push(
      `  ${pad("receipt_id", 10)}  ${pad("seq", 4)}  ${pad("record_type", 18)}  ${pad("tool", 18)}  ${pad("decision", 10)}  ${pad("L1", 6)}  ${pad("L2", 6)}  ${pad("L3", 6)}`
    );
    lines.push(
      `  ${pad("─".repeat(10), 10)}  ${pad("───", 4)}  ${pad("─".repeat(18), 18)}  ${pad("─".repeat(18), 18)}  ${pad("─".repeat(10), 10)}  ${pad("──────", 6)}  ${pad("──────", 6)}  ${pad("──────", 6)}`
    );
    for (const r of rows) {
      lines.push(
        `  ${pad(truncate(r.receipt_id, 10), 10)}  ${pad(String(r.sequence_number), 4)}  ${pad(r.record_type, 18)}  ${pad(r.tool_name ?? "—", 18)}  ${pad(r.decision ?? "—", 10)}  ${pad(r.l1_status, 6)}  ${pad(r.l2_status.split(":")[0], 6)}  ${pad(r.l3_status, 6)}`
      );
    }
  }

  return lines.join("\n");
}

function formatReceiptsJson(rows: ReceiptRow[]): string {
  return JSON.stringify(rows, null, 2);
}

function formatReceiptsCsv(rows: ReceiptRow[]): string {
  if (rows.length === 0) return "";
  const headers = Object.keys(rows[0]) as (keyof ReceiptRow)[];
  const csvLines = [
    headers.join(","),
    ...rows.map((r) =>
      headers
        .map((h) => {
          const val = r[h];
          if (val === null || val === undefined) return "";
          const s = String(val);
          return s.includes(",") || s.includes('"') || s.includes("\n")
            ? `"${s.replace(/"/g, '""')}"`
            : s;
        })
        .join(",")
    ),
  ];
  return csvLines.join("\n");
}

// ── Export ───────────────────────────────────────────────────────────────────

export interface QueryOptions {
  workflowId?: string;
  agent?: string;
  tool?: string;
  decision?: string;
  from?: string;
  to?: string;
  recordType?: string;
  limit?: number;
  format?: "table" | "json" | "csv";
  db?: string;
}

export async function runQuery(options: QueryOptions = {}): Promise<number> {
  const dbFilePath = options.db ?? DEFAULT_DB;
  const fmt = options.format ?? "table";

  let store: ReceiptStore;
  try {
    store = ReceiptStore.open(dbFilePath);
  } catch (err) {
    process.stderr.write(
      `nonsudo query: could not open database ${dbFilePath}: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  try {
    const rows = store.queryReceipts({
      workflow_id: options.workflowId,
      agent_id: options.agent,
      tool_name: options.tool,
      decision: options.decision,
      from: options.from,
      to: options.to,
      record_type: options.recordType,
      limit: options.limit ?? 100,
    });

    if (fmt === "json") {
      process.stdout.write(formatReceiptsJson(rows) + "\n");
      return 0;
    }

    if (fmt === "csv") {
      process.stdout.write(formatReceiptsCsv(rows) + "\n");
      return 0;
    }

    let output = "";

    if (options.workflowId) {
      const wf = store.getWorkflow(options.workflowId);
      if (wf) {
        output += formatWorkflowHeader(wf);
      } else {
        output += `Workflow: ${options.workflowId} (not found in store)\n\n`;
      }
    }

    output += formatReceiptsTable(rows, options.workflowId !== undefined) + "\n";
    process.stdout.write(output);
  } finally {
    store.close();
  }

  return 0;
}
