/**
 * nonsudo index [--file <path>] [--db <path>] [--reverify]
 *
 * Reads an NDJSON receipt file, loads the .tsa sidecar if present, verifies
 * the chain (L1+L2+L3), and inserts all receipts into the receipt store.
 *
 * Idempotent by default: receipts already in the store (matched by source_file)
 * are skipped. Use --reverify to recompute and overwrite L1/L2/L3.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  verifyChain,
  verifySignature,
  loadTsaSidecar,
  SignedReceipt,
  TsaRecord,
} from "@varcore/receipts";
import { ReceiptStore, ReceiptRow, WorkflowRow, TsaTokenRow } from "@varcore/store";
import { resolvePublicKey } from "./verify";

const DEFAULT_DB = path.join(os.homedir(), ".nonsudo", "receipts.db");
const DEFAULT_ACCEPTING_TSA_IDS = ["digicert", "sectigo", "globalsign"];

// ── Helpers ──────────────────────────────────────────────────────────────────

function getPrimaryId(receipt: SignedReceipt): string {
  const r = receipt as unknown as Record<string, unknown>;
  return (r["receipt_id"] ?? r["post_receipt_id"] ?? r["recovery_event_id"] ??
    r["budget_warning_id"] ?? r["reservation_expired_id"] ?? "unknown") as string;
}

function parseReceiptsNdjson(filePath: string): {
  receipts: SignedReceipt[];
  malformedCount: number;
} {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  const receipts: SignedReceipt[] = [];
  let malformedCount = 0;

  for (let i = 0; i < lines.length; i++) {
    try {
      receipts.push(JSON.parse(lines[i]) as SignedReceipt);
    } catch {
      process.stderr.write(
        `[nonsudo index] Warning: malformed JSON on line ${i + 1}, skipping\n`
      );
      malformedCount++;
    }
  }

  return { receipts, malformedCount };
}

function computeL3Status(
  receipt: SignedReceipt,
  tsaById: Map<string, TsaRecord>
): string {
  const record = tsaById.get(getPrimaryId(receipt));
  if (!record) return "SKIPPED";
  if (!DEFAULT_ACCEPTING_TSA_IDS.includes(record.tsa_id)) return "FAIL";
  return "PASS";
}

function buildReceiptRow(
  receipt: SignedReceipt,
  l1Status: string,
  l2Status: string,
  l3Status: string,
  sourceFile: string
): ReceiptRow {
  const r = receipt as unknown as Record<string, unknown>;
  return {
    receipt_id: getPrimaryId(receipt),
    workflow_id: receipt.workflow_id,
    record_type: receipt.record_type,
    sequence_number: receipt.sequence_number,
    agent_id: receipt.agent_id,
    issued_at: receipt.issued_at,
    tool_name: (r["tool_name"] as string) ?? null,
    decision: (r["decision"] as string) ?? null,
    decision_reason: (r["decision_reason"] as string) ?? null,
    blast_radius: (r["blast_radius"] as string) ?? null,
    reversible:
      r["reversible"] !== undefined ? ((r["reversible"] as boolean) ? 1 : 0) : null,
    params_canonical_hash: (r["params_canonical_hash"] as string) ?? null,
    policy_bundle_hash: receipt.policy_bundle_hash,
    queue_status: (r["queue_status"] as string) ?? null,
    failure_reason: (r["failure_reason"] as string) ?? null,
    prev_receipt_hash: receipt.prev_receipt_hash,
    sig: receipt.signature.sig,
    key_id: receipt.signature.key_id,
    l1_status: l1Status,
    l2_status: l2Status,
    l3_status: l3Status,
    source_file: sourceFile,
  };
}

function buildWorkflowRow(
  receipts: SignedReceipt[],
  complete: boolean,
  sourceFile: string
): WorkflowRow | null {
  const manifest = receipts.find((r) => r.record_type === "workflow_manifest");
  if (!manifest) return null;

  const closed = receipts.find(
    (r) => r.record_type === "workflow_closed"
  ) as (SignedReceipt & Record<string, unknown>) | undefined;

  return {
    workflow_id: manifest.workflow_id,
    agent_id: manifest.agent_id,
    workflow_id_source: manifest.workflow_id_source,
    initiated_at: manifest.issued_at,
    closed_at: closed?.issued_at ?? null,
    total_calls: closed ? ((closed["total_calls"] as number) ?? null) : null,
    total_blocked: closed
      ? ((closed["total_blocked"] as number) ?? null)
      : null,
    session_duration_ms: closed
      ? ((closed["session_duration_ms"] as number) ?? null)
      : null,
    close_reason: closed ? ((closed["close_reason"] as string) ?? null) : null,
    complete: complete ? 1 : 0,
    source_file: sourceFile,
  };
}

// ── Export ───────────────────────────────────────────────────────────────────

export interface IndexOptions {
  db?: string;
  reverify?: boolean;
}

export async function runIndex(
  filePath: string,
  options: IndexOptions = {}
): Promise<number> {
  const resolved = path.resolve(filePath);
  const dbFilePath = options.db ?? DEFAULT_DB;

  if (!fs.existsSync(resolved)) {
    process.stderr.write(`nonsudo index: file not found: ${resolved}\n`);
    return 1;
  }

  const { receipts, malformedCount } = parseReceiptsNdjson(resolved);
  if (receipts.length === 0) {
    process.stderr.write(`nonsudo index: no valid receipts found in ${resolved}\n`);
    return 1;
  }

  const dbDir = path.dirname(dbFilePath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  const store = ReceiptStore.open(dbFilePath);

  try {
    if (!options.reverify) {
      const existing = store.countBySourceFile(resolved);
      if (existing > 0 && existing >= receipts.length) {
        process.stdout.write(
          `Indexing ${path.basename(resolved)}\n` +
            `  ${existing} receipts already indexed (use --reverify to recompute)\n\n` +
            `Database: ${dbFilePath}\n`
        );
        return 0;
      }
    }

    const tsaFilePath = resolved + ".tsa";
    const tsaRecords = loadTsaSidecar(tsaFilePath);
    const tsaById = new Map(tsaRecords.map((r) => [r.receipt_id, r]));

    const keyId = receipts[0].signature.key_id;
    let publicKey: Uint8Array;
    try {
      publicKey = await resolvePublicKey(keyId, false);
    } catch (err) {
      process.stderr.write(
        `nonsudo index: ${err instanceof Error ? err.message : String(err)}\n`
      );
      return 1;
    }

    const l1Results: string[] = [];
    for (const receipt of receipts) {
      const sig = await verifySignature(receipt, publicKey);
      l1Results.push(sig.valid ? "PASS" : "FAIL");
    }

    const chainResult = await verifyChain(receipts, publicKey);

    const l2ByReceiptId = new Map<string, string>();
    if (!chainResult.valid) {
      for (const err of chainResult.errors) {
        if (err.code === "L1_INVALID") continue;
        if (err.index >= 0 && err.index < receipts.length) {
          const sortedReceipts = [...receipts].sort(
            (a, b) => a.sequence_number - b.sequence_number
          );
          const receipt = sortedReceipts[err.index];
          if (receipt) {
            l2ByReceiptId.set(getPrimaryId(receipt), `FAIL:${err.code}`);
          }
        }
      }
    }

    let l3PassCount = 0;
    let l3SkipCount = 0;
    let l1FailCount = 0;

    for (let i = 0; i < receipts.length; i++) {
      const receipt = receipts[i];
      const l1Status = l1Results[i];
      const l2Status = l2ByReceiptId.get(getPrimaryId(receipt)) ?? "PASS";
      const l3Status = computeL3Status(receipt, tsaById);

      if (l1Status === "FAIL") l1FailCount++;
      if (l3Status === "PASS") l3PassCount++;
      else if (l3Status === "SKIPPED") l3SkipCount++;

      store.insertReceipt(
        buildReceiptRow(receipt, l1Status, l2Status, l3Status, resolved)
      );
    }

    const workflowIds = [...new Set(receipts.map((r) => r.workflow_id))];
    for (const wfId of workflowIds) {
      const wfReceipts = receipts.filter((r) => r.workflow_id === wfId);
      const wfComplete = chainResult.complete;
      const row = buildWorkflowRow(wfReceipts, wfComplete, resolved);
      if (row) {
        store.upsertWorkflow(row);
      }
    }

    for (const tsaRecord of tsaRecords) {
      const tsaRow: TsaTokenRow = {
        receipt_id: tsaRecord.receipt_id,
        rfc3161_token: tsaRecord.rfc3161_token,
        tsa_id: tsaRecord.tsa_id,
        timestamped_at: tsaRecord.timestamped_at,
      };
      store.insertTsaToken(tsaRow);
    }

    const lines: string[] = [
      `Indexing ${path.basename(resolved)}`,
      `  ${receipts.length} receipt${receipts.length !== 1 ? "s" : ""} read`,
      `  ${workflowIds.length} workflow${workflowIds.length !== 1 ? "s" : ""} indexed`,
      `  ${l3PassCount} receipts with L3: PASS (TSA tokens found in sidecar)`,
      `  ${l3SkipCount} receipts with L3: SKIPPED (no sidecar token)`,
    ];
    if (l1FailCount > 0) {
      lines.push(`  ${l1FailCount} receipts with L1 verification errors`);
    }
    if (malformedCount > 0) {
      lines.push(`  ${malformedCount} malformed lines skipped`);
    }
    lines.push(``, `Database: ${dbFilePath}`);
    process.stdout.write(lines.join("\n") + "\n");
  } finally {
    store.close();
  }

  return 0;
}
