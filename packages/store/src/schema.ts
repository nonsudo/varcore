import type Database from "better-sqlite3";

export const CURRENT_SCHEMA_VERSION = 1;

export function runMigrations(db: Database.Database): void {
  const currentVersion = db.pragma("user_version", { simple: true }) as number;
  if (currentVersion >= CURRENT_SCHEMA_VERSION) return;

  db.exec(`
    CREATE TABLE IF NOT EXISTS receipts (
      receipt_id            TEXT PRIMARY KEY,
      workflow_id           TEXT NOT NULL,
      record_type           TEXT NOT NULL,
      sequence_number       INTEGER NOT NULL,
      agent_id              TEXT NOT NULL,
      issued_at             TEXT NOT NULL,
      tool_name             TEXT,
      decision              TEXT,
      decision_reason       TEXT,
      blast_radius          TEXT,
      reversible            INTEGER,
      params_canonical_hash TEXT,
      policy_bundle_hash    TEXT NOT NULL,
      queue_status          TEXT,
      failure_reason        TEXT,
      prev_receipt_hash     TEXT,
      sig                   TEXT NOT NULL,
      key_id                TEXT NOT NULL,
      l1_status             TEXT NOT NULL,
      l2_status             TEXT NOT NULL,
      l3_status             TEXT NOT NULL,
      source_file           TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_receipts_workflow_id ON receipts(workflow_id);
    CREATE INDEX IF NOT EXISTS idx_receipts_decision     ON receipts(decision);
    CREATE INDEX IF NOT EXISTS idx_receipts_issued_at    ON receipts(issued_at);
    CREATE INDEX IF NOT EXISTS idx_receipts_tool_name    ON receipts(tool_name);

    CREATE TABLE IF NOT EXISTS workflows (
      workflow_id          TEXT PRIMARY KEY,
      agent_id             TEXT NOT NULL,
      workflow_id_source   TEXT NOT NULL,
      initiated_at         TEXT NOT NULL,
      closed_at            TEXT,
      total_calls          INTEGER,
      total_blocked        INTEGER,
      session_duration_ms  INTEGER,
      close_reason         TEXT,
      complete             INTEGER NOT NULL,
      source_file          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tsa_tokens (
      receipt_id      TEXT PRIMARY KEY,
      rfc3161_token   TEXT NOT NULL,
      tsa_id          TEXT NOT NULL,
      timestamped_at  TEXT NOT NULL
    );
  `);

  db.pragma(`user_version = ${CURRENT_SCHEMA_VERSION}`);
}
