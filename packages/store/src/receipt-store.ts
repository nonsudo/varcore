import Database from "better-sqlite3";
import { runMigrations } from "./schema";
import type {
  ReceiptRow,
  WorkflowRow,
  TsaTokenRow,
  ReceiptQuery,
  WorkflowSummary,
} from "./types";

function rowToSummary(row: WorkflowRow): WorkflowSummary {
  return {
    workflow_id: row.workflow_id,
    agent_id: row.agent_id,
    initiated_at: row.initiated_at,
    closed_at: row.closed_at,
    total_calls: row.total_calls,
    total_blocked: row.total_blocked,
    session_duration_ms: row.session_duration_ms,
    close_reason: row.close_reason,
    complete: row.complete === 1,
  };
}

export class ReceiptStore {
  private readonly _db: Database.Database;

  private constructor(db: Database.Database) {
    this._db = db;
  }

  /** Opens or creates the SQLite database. Runs migrations automatically. */
  static open(dbPath: string): ReceiptStore {
    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    runMigrations(db);
    return new ReceiptStore(db);
  }

  /** INSERT OR REPLACE — idempotent on receipt_id. */
  insertReceipt(row: ReceiptRow): void {
    this._db
      .prepare(
        `INSERT OR REPLACE INTO receipts (
          receipt_id, workflow_id, record_type, sequence_number, agent_id, issued_at,
          tool_name, decision, decision_reason, blast_radius, reversible,
          params_canonical_hash, policy_bundle_hash, queue_status, failure_reason,
          prev_receipt_hash, sig, key_id, l1_status, l2_status, l3_status, source_file
        ) VALUES (
          :receipt_id, :workflow_id, :record_type, :sequence_number, :agent_id, :issued_at,
          :tool_name, :decision, :decision_reason, :blast_radius, :reversible,
          :params_canonical_hash, :policy_bundle_hash, :queue_status, :failure_reason,
          :prev_receipt_hash, :sig, :key_id, :l1_status, :l2_status, :l3_status, :source_file
        )`
      )
      .run(row);
  }

  /** INSERT OR REPLACE — idempotent on workflow_id. */
  upsertWorkflow(row: WorkflowRow): void {
    this._db
      .prepare(
        `INSERT OR REPLACE INTO workflows (
          workflow_id, agent_id, workflow_id_source, initiated_at, closed_at,
          total_calls, total_blocked, session_duration_ms, close_reason, complete, source_file
        ) VALUES (
          :workflow_id, :agent_id, :workflow_id_source, :initiated_at, :closed_at,
          :total_calls, :total_blocked, :session_duration_ms, :close_reason, :complete, :source_file
        )`
      )
      .run(row);
  }

  /** INSERT OR REPLACE — idempotent on receipt_id. */
  insertTsaToken(row: TsaTokenRow): void {
    this._db
      .prepare(
        `INSERT OR REPLACE INTO tsa_tokens (receipt_id, rfc3161_token, tsa_id, timestamped_at)
         VALUES (:receipt_id, :rfc3161_token, :tsa_id, :timestamped_at)`
      )
      .run(row);
  }

  /** Returns receipts matching query, ordered by issued_at ASC. */
  queryReceipts(q: ReceiptQuery): ReceiptRow[] {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (q.workflow_id !== undefined) {
      conditions.push("workflow_id = ?");
      params.push(q.workflow_id);
    }
    if (q.agent_id !== undefined) {
      conditions.push("agent_id = ?");
      params.push(q.agent_id);
    }
    if (q.tool_name !== undefined) {
      conditions.push("tool_name = ?");
      params.push(q.tool_name);
    }
    if (q.decision !== undefined) {
      conditions.push("decision = ?");
      params.push(q.decision);
    }
    if (q.record_type !== undefined) {
      conditions.push("record_type = ?");
      params.push(q.record_type);
    }
    if (q.from !== undefined) {
      conditions.push("issued_at >= ?");
      params.push(q.from);
    }
    if (q.to !== undefined) {
      conditions.push("issued_at <= ?");
      params.push(q.to + "T23:59:59Z");
    }

    const where =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = q.limit ?? 100;
    const offset = q.offset ?? 0;

    return this._db
      .prepare(
        `SELECT * FROM receipts ${where} ORDER BY issued_at ASC LIMIT ? OFFSET ?`
      )
      .all([...params, limit, offset]) as ReceiptRow[];
  }

  /** All workflows, ordered by initiated_at DESC. */
  listWorkflows(): WorkflowSummary[] {
    const rows = this._db
      .prepare(`SELECT * FROM workflows ORDER BY initiated_at DESC`)
      .all() as WorkflowRow[];
    return rows.map(rowToSummary);
  }

  /** Single workflow by id, or null. */
  getWorkflow(workflowId: string): WorkflowSummary | null {
    const row = this._db
      .prepare(`SELECT * FROM workflows WHERE workflow_id = ?`)
      .get(workflowId) as WorkflowRow | undefined;
    return row ? rowToSummary(row) : null;
  }

  /** All receipts for a workflow, ordered by sequence_number ASC. */
  getWorkflowReceipts(workflowId: string): ReceiptRow[] {
    return this._db
      .prepare(
        `SELECT * FROM receipts WHERE workflow_id = ? ORDER BY sequence_number ASC`
      )
      .all(workflowId) as ReceiptRow[];
  }

  /** Receipt count for a given source file. Used by nonsudo index for progress reporting. */
  countBySourceFile(sourceFile: string): number {
    const row = this._db
      .prepare(
        `SELECT COUNT(*) as count FROM receipts WHERE source_file = ?`
      )
      .get(sourceFile) as { count: number };
    return row.count;
  }

  /** TSA token for a receipt, or null if not stored. */
  getTsaToken(receiptId: string): TsaTokenRow | null {
    const row = this._db
      .prepare(`SELECT * FROM tsa_tokens WHERE receipt_id = ?`)
      .get(receiptId) as TsaTokenRow | undefined;
    return row ?? null;
  }

  close(): void {
    this._db.close();
  }
}
