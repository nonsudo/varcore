/**
 * Tests for ReceiptStore (S1–S20).
 *
 * S1  ReceiptStore.open() creates database if it doesn't exist
 * S2  insertReceipt and queryReceipts round-trip — all fields preserved
 * S3  insertReceipt is idempotent — second call with same receipt_id produces one row
 * S4  queryReceipts filters by workflow_id
 * S5  queryReceipts filters by decision
 * S6  queryReceipts filters by tool_name
 * S7  queryReceipts filters by from / to date range
 * S8  queryReceipts respects limit and offset
 * S9  upsertWorkflow sets complete: true when workflow_closed present
 * S10 upsertWorkflow sets complete: false when no workflow_closed
 * S11 getWorkflow returns null for unknown workflow_id
 * S12 listWorkflows returns all workflows ordered by initiated_at DESC
 * S13 getWorkflowReceipts returns receipts ordered by sequence_number ASC
 * S14 insertTsaToken stores token and can be retrieved
 * S15 countBySourceFile returns correct count
 * S16 close() releases database — subsequent operations throw
 * S17 Schema migration runs on open — PRAGMA user_version set correctly
 * S18 queryReceipts with no filters returns all receipts up to limit
 * S19 INSERT OR REPLACE on upsertWorkflow updates existing row correctly
 * S20 ReceiptStore handles empty database — all queries return empty arrays
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ReceiptStore } from "../receipt-store";
import { CURRENT_SCHEMA_VERSION } from "../schema";
import Database from "better-sqlite3";
import type { ReceiptRow, WorkflowRow, TsaTokenRow } from "../types";

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeReceiptRow(overrides: Partial<ReceiptRow> = {}): ReceiptRow {
  return {
    receipt_id: "r-" + Math.random().toString(36).slice(2),
    workflow_id: "wf-01",
    record_type: "action_receipt",
    sequence_number: 1,
    agent_id: "test-agent",
    issued_at: "2026-03-01T10:00:00Z",
    tool_name: "bash",
    decision: "ALLOW",
    decision_reason: "policy allows",
    blast_radius: "LOW",
    reversible: 1,
    params_canonical_hash: "sha256:" + "a".repeat(64),
    policy_bundle_hash: "sha256:" + "0".repeat(64),
    queue_status: "COMPLETED",
    failure_reason: null,
    prev_receipt_hash: null,
    sig: "AAAAsig",
    key_id: "test-key",
    l1_status: "PASS",
    l2_status: "PASS",
    l3_status: "SKIPPED",
    source_file: "/tmp/receipts.ndjson",
    ...overrides,
  };
}

function makeWorkflowRow(overrides: Partial<WorkflowRow> = {}): WorkflowRow {
  return {
    workflow_id: "wf-01",
    agent_id: "test-agent",
    workflow_id_source: "nonsudo_generated",
    initiated_at: "2026-03-01T10:00:00Z",
    closed_at: "2026-03-01T10:05:00Z",
    total_calls: 5,
    total_blocked: 1,
    session_duration_ms: 300000,
    close_reason: "explicit_close",
    complete: 1,
    source_file: "/tmp/receipts.ndjson",
    ...overrides,
  };
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe("ReceiptStore", () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-store-"));
    dbPath = path.join(tmpDir, "receipts.db");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // S1: open() creates database if it doesn't exist
  test("S1: ReceiptStore.open() creates database if it does not exist", () => {
    expect(fs.existsSync(dbPath)).toBe(false);
    const store = ReceiptStore.open(dbPath);
    store.close();
    expect(fs.existsSync(dbPath)).toBe(true);
  });

  // S2: round-trip all fields
  test("S2: insertReceipt and queryReceipts round-trip — all fields preserved", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const row = makeReceiptRow({
        receipt_id: "r-s2",
        workflow_id: "wf-s2",
        tool_name: "stripe_charge",
        decision: "BLOCK",
        l1_status: "PASS",
        l2_status: "PASS",
        l3_status: "PASS",
      });
      store.insertReceipt(row);

      const results = store.queryReceipts({ workflow_id: "wf-s2" });
      expect(results).toHaveLength(1);
      expect(results[0].receipt_id).toBe("r-s2");
      expect(results[0].tool_name).toBe("stripe_charge");
      expect(results[0].decision).toBe("BLOCK");
      expect(results[0].l1_status).toBe("PASS");
      expect(results[0].l3_status).toBe("PASS");
    } finally {
      store.close();
    }
  });

  // S3: idempotency — second insert with same receipt_id produces one row
  test("S3: insertReceipt is idempotent — second call produces one row", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const row = makeReceiptRow({ receipt_id: "r-s3", workflow_id: "wf-s3" });
      store.insertReceipt(row);
      store.insertReceipt(row); // second call

      const results = store.queryReceipts({ workflow_id: "wf-s3" });
      expect(results).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  // S4: filter by workflow_id
  test("S4: queryReceipts filters by workflow_id", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s4a", workflow_id: "wf-A" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s4b", workflow_id: "wf-B" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s4c", workflow_id: "wf-A" }));

      const resultsA = store.queryReceipts({ workflow_id: "wf-A" });
      expect(resultsA).toHaveLength(2);
      expect(resultsA.every((r) => r.workflow_id === "wf-A")).toBe(true);

      const resultsB = store.queryReceipts({ workflow_id: "wf-B" });
      expect(resultsB).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  // S5: filter by decision
  test("S5: queryReceipts filters by decision", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s5a", decision: "ALLOW" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s5b", decision: "BLOCK" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s5c", decision: "BLOCK" }));

      const blocked = store.queryReceipts({ decision: "BLOCK" });
      expect(blocked).toHaveLength(2);
      expect(blocked.every((r) => r.decision === "BLOCK")).toBe(true);

      const allowed = store.queryReceipts({ decision: "ALLOW" });
      expect(allowed).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  // S6: filter by tool_name
  test("S6: queryReceipts filters by tool_name", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s6a", tool_name: "bash" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s6b", tool_name: "stripe" }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s6c", tool_name: "bash" }));

      const bash = store.queryReceipts({ tool_name: "bash" });
      expect(bash).toHaveLength(2);
      expect(bash.every((r) => r.tool_name === "bash")).toBe(true);
    } finally {
      store.close();
    }
  });

  // S7: filter by from / to date range
  test("S7: queryReceipts filters by from / to date range", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.insertReceipt(
        makeReceiptRow({ receipt_id: "r-s7a", issued_at: "2026-01-01T00:00:00Z" })
      );
      store.insertReceipt(
        makeReceiptRow({ receipt_id: "r-s7b", issued_at: "2026-03-01T00:00:00Z" })
      );
      store.insertReceipt(
        makeReceiptRow({ receipt_id: "r-s7c", issued_at: "2026-05-01T00:00:00Z" })
      );

      const results = store.queryReceipts({ from: "2026-02-01", to: "2026-04-01" });
      expect(results).toHaveLength(1);
      expect(results[0].receipt_id).toBe("r-s7b");
    } finally {
      store.close();
    }
  });

  // S8: limit and offset
  test("S8: queryReceipts respects limit and offset", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      for (let i = 0; i < 5; i++) {
        store.insertReceipt(
          makeReceiptRow({
            receipt_id: `r-s8-${i}`,
            issued_at: `2026-03-0${i + 1}T00:00:00Z`,
          })
        );
      }

      const page1 = store.queryReceipts({ limit: 2, offset: 0 });
      expect(page1).toHaveLength(2);

      const page2 = store.queryReceipts({ limit: 2, offset: 2 });
      expect(page2).toHaveLength(2);

      // No overlap
      expect(page1[0].receipt_id).not.toBe(page2[0].receipt_id);

      const page3 = store.queryReceipts({ limit: 2, offset: 4 });
      expect(page3).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  // S9: upsertWorkflow with complete = 1
  test("S9: upsertWorkflow sets complete: true when workflow_closed present", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.upsertWorkflow(
        makeWorkflowRow({ workflow_id: "wf-s9", complete: 1, closed_at: "2026-03-01T10:05:00Z" })
      );

      const wf = store.getWorkflow("wf-s9");
      expect(wf).not.toBeNull();
      if (!wf) throw new Error("Expected wf-s9 workflow to exist");
      expect(wf.complete).toBe(true);
      expect(wf.closed_at).toBe("2026-03-01T10:05:00Z");
    } finally {
      store.close();
    }
  });

  // S10: upsertWorkflow with complete = 0
  test("S10: upsertWorkflow sets complete: false when no workflow_closed", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.upsertWorkflow(
        makeWorkflowRow({
          workflow_id: "wf-s10",
          complete: 0,
          closed_at: null,
          total_calls: null,
          total_blocked: null,
          session_duration_ms: null,
          close_reason: null,
        })
      );

      const wf = store.getWorkflow("wf-s10");
      expect(wf).not.toBeNull();
      if (!wf) throw new Error("Expected wf-s10 workflow to exist");
      expect(wf.complete).toBe(false);
      expect(wf.closed_at).toBeNull();
    } finally {
      store.close();
    }
  });

  // S11: getWorkflow returns null for unknown workflow_id
  test("S11: getWorkflow returns null for unknown workflow_id", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const wf = store.getWorkflow("does-not-exist");
      expect(wf).toBeNull();
    } finally {
      store.close();
    }
  });

  // S12: listWorkflows ordered by initiated_at DESC
  test("S12: listWorkflows returns all workflows ordered by initiated_at DESC", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.upsertWorkflow(
        makeWorkflowRow({ workflow_id: "wf-s12a", initiated_at: "2026-01-01T00:00:00Z" })
      );
      store.upsertWorkflow(
        makeWorkflowRow({ workflow_id: "wf-s12b", initiated_at: "2026-03-01T00:00:00Z" })
      );
      store.upsertWorkflow(
        makeWorkflowRow({ workflow_id: "wf-s12c", initiated_at: "2026-02-01T00:00:00Z" })
      );

      const workflows = store.listWorkflows();
      expect(workflows).toHaveLength(3);
      expect(workflows[0].workflow_id).toBe("wf-s12b"); // most recent first
      expect(workflows[1].workflow_id).toBe("wf-s12c");
      expect(workflows[2].workflow_id).toBe("wf-s12a");
    } finally {
      store.close();
    }
  });

  // S13: getWorkflowReceipts ordered by sequence_number ASC
  test("S13: getWorkflowReceipts returns receipts ordered by sequence_number ASC", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      // Insert out of order
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s13c", workflow_id: "wf-s13", sequence_number: 2 }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s13a", workflow_id: "wf-s13", sequence_number: 0 }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s13b", workflow_id: "wf-s13", sequence_number: 1 }));

      const receipts = store.getWorkflowReceipts("wf-s13");
      expect(receipts).toHaveLength(3);
      expect(receipts[0].sequence_number).toBe(0);
      expect(receipts[1].sequence_number).toBe(1);
      expect(receipts[2].sequence_number).toBe(2);
    } finally {
      store.close();
    }
  });

  // S14: insertTsaToken stores token
  test("S14: insertTsaToken stores token and can be queried via raw DB", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const token: TsaTokenRow = {
        receipt_id: "r-s14",
        rfc3161_token: Buffer.from("fake-der").toString("base64"),
        tsa_id: "digicert",
        timestamped_at: "2026-03-01T10:00:00Z",
      };
      store.insertTsaToken(token);
    } finally {
      store.close();
    }

    // Verify by opening the raw DB
    const raw = new Database(dbPath, { readonly: true });
    const rows = raw.prepare("SELECT * FROM tsa_tokens WHERE receipt_id = ?").all("r-s14") as TsaTokenRow[];
    raw.close();

    expect(rows).toHaveLength(1);
    expect(rows[0].tsa_id).toBe("digicert");
    expect(rows[0].rfc3161_token).toBe(Buffer.from("fake-der").toString("base64"));
  });

  // S14b: insertTsaToken is idempotent (INSERT OR REPLACE)
  test("S14b: insertTsaToken is idempotent (INSERT OR REPLACE)", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const token: TsaTokenRow = {
        receipt_id: "r-s14b",
        rfc3161_token: "old-token",
        tsa_id: "digicert",
        timestamped_at: "2026-03-01T00:00:00Z",
      };
      store.insertTsaToken(token);
      store.insertTsaToken({ ...token, rfc3161_token: "new-token" });
    } finally {
      store.close();
    }

    const raw = new Database(dbPath, { readonly: true });
    const rows = raw.prepare("SELECT * FROM tsa_tokens WHERE receipt_id = ?").all("r-s14b") as TsaTokenRow[];
    raw.close();

    expect(rows).toHaveLength(1);
    expect(rows[0].rfc3161_token).toBe("new-token");
  });

  // S15: countBySourceFile
  test("S15: countBySourceFile returns correct count", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      const sourceFile = "/tmp/test-s15.ndjson";
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s15a", source_file: sourceFile }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s15b", source_file: sourceFile }));
      store.insertReceipt(makeReceiptRow({ receipt_id: "r-s15c", source_file: "/tmp/other.ndjson" }));

      expect(store.countBySourceFile(sourceFile)).toBe(2);
      expect(store.countBySourceFile("/tmp/other.ndjson")).toBe(1);
      expect(store.countBySourceFile("/tmp/missing.ndjson")).toBe(0);
    } finally {
      store.close();
    }
  });

  // S16: close() releases database — subsequent operations throw
  test("S16: close() releases database — subsequent operations throw", () => {
    const store = ReceiptStore.open(dbPath);
    store.close();

    // better-sqlite3 throws after close()
    expect(() => store.queryReceipts({})).toThrow();
  });

  // S17: PRAGMA user_version is set by migration
  test("S17: schema migration runs on open — PRAGMA user_version set correctly", () => {
    const store = ReceiptStore.open(dbPath);
    store.close();

    // Verify user_version via raw DB
    const raw = new Database(dbPath, { readonly: true });
    const version = raw.pragma("user_version", { simple: true }) as number;
    raw.close();

    expect(version).toBe(CURRENT_SCHEMA_VERSION);
  });

  // S18: queryReceipts with no filters returns all receipts up to limit
  test("S18: queryReceipts with no filters returns all receipts up to limit", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      for (let i = 0; i < 5; i++) {
        store.insertReceipt(makeReceiptRow({ receipt_id: `r-s18-${i}` }));
      }

      const all = store.queryReceipts({ limit: 10 });
      expect(all).toHaveLength(5);

      const limited = store.queryReceipts({ limit: 3 });
      expect(limited).toHaveLength(3);
    } finally {
      store.close();
    }
  });

  // S19: upsertWorkflow INSERT OR REPLACE updates existing row
  test("S19: INSERT OR REPLACE on upsertWorkflow updates existing row correctly", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      store.upsertWorkflow(
        makeWorkflowRow({
          workflow_id: "wf-s19",
          total_calls: 5,
          complete: 0,
          closed_at: null,
        })
      );

      // Update with workflow_closed
      store.upsertWorkflow(
        makeWorkflowRow({
          workflow_id: "wf-s19",
          total_calls: 10,
          complete: 1,
          closed_at: "2026-03-01T11:00:00Z",
        })
      );

      const wf = store.getWorkflow("wf-s19");
      expect(wf).not.toBeNull();
      if (!wf) throw new Error("Expected wf-s19 workflow to exist");
      expect(wf.total_calls).toBe(10);
      expect(wf.complete).toBe(true);
      expect(wf.closed_at).toBe("2026-03-01T11:00:00Z");

      // Only one workflow in store
      expect(store.listWorkflows()).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  // S20: empty database — all queries return empty arrays
  test("S20: ReceiptStore handles empty database — all queries return empty arrays", () => {
    const store = ReceiptStore.open(dbPath);
    try {
      expect(store.queryReceipts({})).toEqual([]);
      expect(store.listWorkflows()).toEqual([]);
      expect(store.getWorkflow("anything")).toBeNull();
      expect(store.getWorkflowReceipts("anything")).toEqual([]);
      expect(store.countBySourceFile("anything")).toBe(0);
    } finally {
      store.close();
    }
  });
});
