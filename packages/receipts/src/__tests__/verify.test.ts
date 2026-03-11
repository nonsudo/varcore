/**
 * Tests for L3 verification: loadTsaSidecar + verifyL3 (R1–R8).
 *
 * R1: loadTsaSidecar returns [] when file does not exist
 * R2: loadTsaSidecar parses NDJSON records correctly
 * R3: verifyL3 returns SKIPPED when no tsaRecords provided
 * R4: verifyL3 returns PASS when all receipts have valid TSA records with allowlisted tsa_id
 * R5: verifyL3 returns FAIL when a receipt's tsa_id is not in accepting_tsa_ids
 * R6: verifyL3 returns SKIPPED for receipt without sidecar entry (mixed PASS/SKIPPED = PASS)
 * R7: verifyL3 returns FAIL when any receipt has non-allowlisted tsa_id
 * R8: verifyL3 uses default accepting_tsa_ids ["digicert","sectigo","globalsign"]
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ed from "@noble/ed25519";
import { loadTsaSidecar, verifyL3, verifyChain, createReceipt, signReceipt, chainReceipt } from "../index";
import type { TsaRecord, ChainVerificationResult } from "../index";
import type { SignedReceipt, ReceiptFields, PostReceiptFields } from "../types";
import { buildRfc3161Token } from "../test-utils";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fakeReceipt(id: string): SignedReceipt {
  return {
    receipt_id: id,
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: "wf-01",
    workflow_id_source: "nonsudo_generated",
    agent_id: "test-agent",
    issued_at: "2026-02-28T00:00:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: "sha256:" + "0".repeat(64),
    rfc3161_token: null,
    tsa_id: null,
    initiator_id: "test",
    workflow_owner: "team",
    session_budget: { api_calls: 100 },
    declared_tools: [],
    capability_manifest_hash: null,
    parent_workflow_id: null,
    framework_ref: null,
    signature: { alg: "Ed25519", key_id: "key", sig: "AAAA" },
  } as SignedReceipt;
}

function fakeTsaRecord(receipt: SignedReceipt, tsaId = "digicert"): TsaRecord {
  const r = receipt as unknown as Record<string, unknown>;
  return {
    receipt_id: (r["receipt_id"] ?? r["post_receipt_id"] ?? r["recovery_event_id"] ??
      r["budget_warning_id"] ?? r["reservation_expired_id"] ?? "unknown") as string,
    rfc3161_token: buildRfc3161Token(receipt),
    tsa_id: tsaId,
    timestamped_at: "2026-02-28T00:00:00Z",
  };
}

// ── loadTsaSidecar tests ──────────────────────────────────────────────────────

describe("loadTsaSidecar", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ns-l3-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("R1: returns [] when sidecar file does not exist", () => {
    const records = loadTsaSidecar(path.join(tmpDir, "nonexistent.tsa"));
    expect(records).toEqual([]);
  });

  test("R2: parses NDJSON records correctly", () => {
    const tsaPath = path.join(tmpDir, "receipts.tsa");
    // loadTsaSidecar only parses NDJSON — DER content doesn't matter here
    const r1: TsaRecord = { receipt_id: "receipt-01", rfc3161_token: "dGVzdA==", tsa_id: "digicert", timestamped_at: "2026-02-28T00:00:00Z" };
    const r2: TsaRecord = { receipt_id: "receipt-02", rfc3161_token: "dGVzdA==", tsa_id: "sectigo", timestamped_at: "2026-02-28T00:00:00Z" };
    fs.writeFileSync(
      tsaPath,
      [JSON.stringify(r1), JSON.stringify(r2)].join("\n") + "\n"
    );

    const records = loadTsaSidecar(tsaPath);
    expect(records).toHaveLength(2);
    expect(records[0].receipt_id).toBe("receipt-01");
    expect(records[0].tsa_id).toBe("digicert");
    expect(records[1].receipt_id).toBe("receipt-02");
    expect(records[1].tsa_id).toBe("sectigo");
  });
});

// ── verifyL3 tests ────────────────────────────────────────────────────────────

describe("verifyL3", () => {
  test("R3: returns SKIPPED when tsaRecords is empty (no sidecar entries)", async () => {
    const receipts = [fakeReceipt("r-01"), fakeReceipt("r-02")];
    const result = await verifyL3(receipts, []);
    expect(result.status).toBe("SKIPPED");
  });

  test("R4: returns PASS when all receipts have allowlisted tsa_id", async () => {
    const r01 = fakeReceipt("r-01");
    const r02 = fakeReceipt("r-02");
    const tsaRecords = [
      fakeTsaRecord(r01, "digicert"),
      fakeTsaRecord(r02, "sectigo"),
    ];
    const result = await verifyL3([r01, r02], tsaRecords);
    expect(result.status).toBe("PASS");
  });

  test("R5: returns FAIL when a receipt's tsa_id is not in accepting_tsa_ids", async () => {
    const r01 = fakeReceipt("r-01");
    const tsaRecords = [fakeTsaRecord(r01, "evilcorp-tsa")];
    const result = await verifyL3([r01], tsaRecords);
    expect(result.status).toBe("FAIL");
    expect(result.failed_receipt_id).toBe("r-01");
    expect(result.reason).toBe("tsa_not_in_allowlist");
  });

  test("R6: receipt without sidecar entry = SKIPPED; with entry = PASS; overall = PASS", async () => {
    // r-01 has a record (PASS), r-02 has no record (SKIPPED) → overall PASS
    const r01 = fakeReceipt("r-01");
    const r02 = fakeReceipt("r-02");
    const tsaRecords = [fakeTsaRecord(r01, "digicert")]; // only r-01
    const result = await verifyL3([r01, r02], tsaRecords);
    expect(result.status).toBe("PASS");
  });

  test("R7: FAIL when any receipt has non-allowlisted tsa_id (even if others PASS)", async () => {
    const r01 = fakeReceipt("r-01");
    const r02 = fakeReceipt("r-02");
    const tsaRecords = [
      fakeTsaRecord(r01, "digicert"),   // PASS
      fakeTsaRecord(r02, "bad-tsa"),     // FAIL
    ];
    const result = await verifyL3([r01, r02], tsaRecords);
    expect(result.status).toBe("FAIL");
    expect(result.failed_receipt_id).toBe("r-02");
  });

  test("R8: uses default accepting_tsa_ids when not specified", async () => {
    const r01 = fakeReceipt("r-01");

    // "globalsign" is in the default list → PASS
    const result1 = await verifyL3([r01], [fakeTsaRecord(r01, "globalsign")]);
    expect(result1.status).toBe("PASS");

    // "unknown-tsa" is NOT in the default list → FAIL
    const result2 = await verifyL3([r01], [fakeTsaRecord(r01, "unknown-tsa")]);
    expect(result2.status).toBe("FAIL");
  });

  // ── BP1–BP2: v1.1 batch PENDING branch ──────────────────────────────────────

  test("BP1: PENDING branch does not fire on v1.0 receipts — batch_id absent → falls through to existing L3 logic", async () => {
    // Standard v1.0 receipts have no batch_id field — the branch must be skipped.
    const r01 = fakeReceipt("r-01");
    const r02 = fakeReceipt("r-02");

    // No batch_id → batch branch skipped → SKIPPED (no sidecar entries)
    const result = await verifyL3([r01, r02], []);
    expect(result.status).toBe("SKIPPED");

    // With a per-receipt sidecar entry → PASS (existing logic unaffected)
    const result2 = await verifyL3([r01], [fakeTsaRecord(r01, "digicert")]);
    expect(result2.status).toBe("PASS");
  });

  test("BP2: PENDING branch fires when receipt has batch_id and a matching batch sidecar entry exists", async () => {
    // Simulate a v1.1 receipt by casting — batch_id is not in the v1.0 type,
    // this mirrors the forward-compatibility probe in verifyL3.
    const r01 = {
      ...fakeReceipt("r-01"),
      batch_id: "batch-0101",
    } as unknown as SignedReceipt;

    // A batch-type sidecar entry (entry_type: "batch")
    const batchEntry = {
      entry_type: "batch",
      batch_id: "batch-0101",
      merkle_root: "a".repeat(64),
      tsa_id: "digicert",
      rfc3161_token: "placeholder",
      receipt_count: 1,
      closed_at: "2026-02-28T00:00:00Z",
    } as unknown as TsaRecord;

    const result = await verifyL3([r01], [batchEntry]);
    expect(result.status).toBe("PENDING");
  });
});

// ── WC1–WC6: verifyChain — complete flag and receipt sorting ──────────────────

describe("verifyChain — complete flag and sorting (WC1–WC6)", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;

  const ZERO_HASH = "sha256:" + "0".repeat(64);
  const KEY_ID = "wc-test-key";

  beforeAll(async () => {
    privKey = ed.utils.randomPrivateKey();
    pubKey = await ed.getPublicKeyAsync(privKey);
  });

  function wcManifestFields(seq = 0, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `wc-manifest-${seq}`,
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: "wf-wc",
      workflow_id_source: "nonsudo_generated",
      agent_id: "wc-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: "wc-test",
      workflow_owner: "wc-team",
      session_budget: { api_calls: 100 },
      declared_tools: [],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
    };
  }

  function wcActionFields(seq: number, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `wc-action-${seq}`,
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: "wf-wc",
      workflow_id_source: "nonsudo_generated",
      agent_id: "wc-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: "bash",
      params_canonical_hash: ZERO_HASH,
      decision: "ALLOW",
      decision_reason: "test",
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: "LOW",
      reversible: true,
      state_version_before: seq - 1,
      state_version_after: seq,
      response_hash: null,
    };
  }

  function wcClosedFields(seq: number, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `wc-closed-${seq}`,
      record_type: "workflow_closed",
      spec_version: "var/1.0",
      workflow_id: "wf-wc",
      workflow_id_source: "nonsudo_generated",
      agent_id: "wc-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      total_calls: seq,
      total_blocked: 0,
      total_spend: null,
      session_duration_ms: 1000,
      close_reason: "explicit_close",
    };
  }

  // WC1: complete: true when workflow_closed is the last receipt
  test("WC1: verifyChain returns complete:true when workflow_closed is last receipt", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sa = await signReceipt(chainReceipt(createReceipt(wcActionFields(1)), sm), privKey, KEY_ID);
    const sc = await signReceipt(chainReceipt(createReceipt(wcClosedFields(2)), sa), privKey, KEY_ID);

    const result = await verifyChain([sm, sa, sc], pubKey);
    expect(result.valid).toBe(true);
    expect(result.complete).toBe(true);
  });

  // WC2: complete: false when no workflow_closed present
  test("WC2: verifyChain returns complete:false when no workflow_closed present", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sa = await signReceipt(chainReceipt(createReceipt(wcActionFields(1)), sm), privKey, KEY_ID);

    const result = await verifyChain([sm, sa], pubKey);
    expect(result.valid).toBe(true);
    expect(result.complete).toBe(false);
  });

  // WC3: FAIL when workflow_closed.prev_receipt_hash doesn't match preceding receipt
  test("WC3: verifyChain fails when workflow_closed prev_receipt_hash is wrong", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sa = await signReceipt(chainReceipt(createReceipt(wcActionFields(1)), sm), privKey, KEY_ID);

    // Create workflow_closed chained correctly, then tamper prev_receipt_hash
    const chained = chainReceipt(createReceipt(wcClosedFields(2)), sa);
    (chained as unknown as Record<string, unknown>)["prev_receipt_hash"] = "sha256:" + "f".repeat(64);
    const sc = await signReceipt(chained, privKey, KEY_ID);

    const result = await verifyChain([sm, sa, sc], pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === "HASH_MISMATCH")).toBe(true);
  });

  // WC4: manifest → workflow_closed with no action receipts between them
  test("WC4: verifyChain handles manifest → workflow_closed with no action receipts", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sc = await signReceipt(chainReceipt(createReceipt(wcClosedFields(1)), sm), privKey, KEY_ID);

    const result = await verifyChain([sm, sc], pubKey);
    expect(result.valid).toBe(true);
    expect(result.complete).toBe(true);
    expect(result.gaps).toEqual([]);
  });

  // WC5: out-of-order receipts are sorted by sequence_number
  test("WC5: verifyChain sorts by sequence_number — out-of-order NDJSON is valid", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sa = await signReceipt(chainReceipt(createReceipt(wcActionFields(1)), sm), privKey, KEY_ID);
    const sc = await signReceipt(chainReceipt(createReceipt(wcClosedFields(2)), sa), privKey, KEY_ID);

    // Pass receipts in reverse order — verifyChain must sort them first
    const result = await verifyChain([sc, sa, sm], pubKey);
    expect(result.valid).toBe(true);
    expect(result.complete).toBe(true);
    expect(result.gaps).toEqual([]);
  });

  // WC6: ChainVerificationResult.complete is always a boolean (type + runtime check)
  test("WC6: ChainVerificationResult has complete: boolean — existing callers unaffected", async () => {
    const sm = await signReceipt(createReceipt(wcManifestFields(0)), privKey, KEY_ID);
    const sc = await signReceipt(chainReceipt(createReceipt(wcClosedFields(1)), sm), privKey, KEY_ID);

    // TypeScript type annotation ensures complete is part of the interface
    const result1: ChainVerificationResult = await verifyChain([sm, sc], pubKey);
    expect(typeof result1.complete).toBe("boolean");
    expect(result1.complete).toBe(true);

    const result2: ChainVerificationResult = await verifyChain([sm], pubKey);
    expect(typeof result2.complete).toBe("boolean");
    expect(result2.complete).toBe(false);
  });
});

// ── MM1, WM1: MISSING_MANIFEST + WORKFLOW_ID_MISMATCH ────────────────────────

describe("verifyChain — MISSING_MANIFEST + WORKFLOW_ID_MISMATCH (MM1, WM1)", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;

  const ZERO_HASH = "sha256:" + "0".repeat(64);
  const KEY_ID = "mm-test-key";

  beforeAll(async () => {
    privKey = ed.utils.randomPrivateKey();
    pubKey = await ed.getPublicKeyAsync(privKey);
  });

  function mmManifestFields(seq: number, wfId: string, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `mm-manifest-${seq}`,
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: wfId,
      workflow_id_source: "nonsudo_generated",
      agent_id: "mm-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: "mm-test",
      workflow_owner: "mm-team",
      session_budget: { api_calls: 100 },
      declared_tools: [],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
    };
  }

  function mmActionFields(seq: number, wfId: string, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `mm-action-${seq}`,
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: wfId,
      workflow_id_source: "nonsudo_generated",
      agent_id: "mm-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: "bash",
      params_canonical_hash: ZERO_HASH,
      decision: "ALLOW",
      decision_reason: "test",
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: "LOW",
      reversible: true,
      state_version_before: seq - 1,
      state_version_after: seq,
      response_hash: null,
    };
  }

  test("MM1: verifyChain fails with MISSING_MANIFEST when first receipt is not workflow_manifest", async () => {
    // action_receipt as the first receipt — no manifest
    const sa = await signReceipt(createReceipt(mmActionFields(0, "wf-mm")), privKey, KEY_ID);
    const result = await verifyChain([sa], pubKey);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === "MISSING_MANIFEST")).toBe(true);
    const mmErr = result.errors.find((e) => e.code === "MISSING_MANIFEST");
    if (!mmErr) throw new Error("MISSING_MANIFEST error not found");
    expect(mmErr.index).toBe(0);
    expect(mmErr.message).toContain("expected workflow_manifest");
  });

  test("WM1: verifyChain fails with WORKFLOW_ID_MISMATCH when receipts have different workflow_ids", async () => {
    const sm = await signReceipt(createReceipt(mmManifestFields(0, "wf-A")), privKey, KEY_ID);
    // Second receipt belongs to a different workflow
    const a2Fields = mmActionFields(1, "wf-B");
    const a2Chained = chainReceipt(createReceipt(a2Fields), sm);
    const sa = await signReceipt(a2Chained, privKey, KEY_ID);

    const result = await verifyChain([sm, sa], pubKey);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === "WORKFLOW_ID_MISMATCH")).toBe(true);
    const wmErr = result.errors.find((e) => e.code === "WORKFLOW_ID_MISMATCH");
    if (!wmErr) throw new Error("WORKFLOW_ID_MISMATCH error not found");
    expect(wmErr.index).toBe(1);
    expect(wmErr.message).toContain("wf-B");
    expect(wmErr.message).toContain("wf-A");
  });
});

// ── C3, D1, D2: spec_version, DEGRADED_STATE, MONEY_ACTION_TAG_MISSING ────────

describe("verifyChain — C3/D1/D2 checks (spec_version + warnings)", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;

  const ZERO_HASH = "sha256:" + "0".repeat(64);
  const KEY_ID = "spec-test-key";

  beforeAll(async () => {
    privKey = ed.utils.randomPrivateKey();
    pubKey = await ed.getPublicKeyAsync(privKey);
  });

  function specManifestFields(wfId: string, seq = 0, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `spec-manifest-${wfId}-${seq}`,
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: wfId,
      workflow_id_source: "nonsudo_generated",
      agent_id: "spec-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: "spec-test",
      workflow_owner: "spec-team",
      session_budget: { api_calls: 100 },
      declared_tools: [],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
    };
  }

  function specActionFields(wfId: string, seq: number, prevHash: string | null = null): ReceiptFields {
    return {
      receipt_id: `spec-action-${wfId}-${seq}`,
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: wfId,
      workflow_id_source: "nonsudo_generated",
      agent_id: "spec-agent",
      issued_at: "2026-03-01T00:00:00Z",
      prev_receipt_hash: prevHash,
      sequence_number: seq,
      policy_bundle_hash: ZERO_HASH,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: "bash",
      params_canonical_hash: ZERO_HASH,
      decision: "ALLOW",
      decision_reason: "test",
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: "LOW",
      reversible: true,
      state_version_before: seq - 1,
      state_version_after: seq,
      response_hash: null,
    };
  }

  // ── C3 ─────────────────────────────────────────────────────────────────────

  test("C3: receipt with spec_version!='var/1.0' → FAIL UNKNOWN_SPEC_VERSION", async () => {
    // Build manifest with a bogus spec_version — cast to bypass TypeScript literal type
    const badManifest = createReceipt({
      ...specManifestFields("c3-wf", 0, null),
      spec_version: "var/99.0" as "var/1.0",
    });
    // Sign covers the bad spec_version value — L1 will PASS, C3 check will flag it
    const sm = await signReceipt(badManifest, privKey, KEY_ID);

    const result = await verifyChain([sm], pubKey);

    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.code === "UNKNOWN_SPEC_VERSION")).toBe(true);
    const c3Err = result.errors.find((e) => e.code === "UNKNOWN_SPEC_VERSION");
    if (!c3Err) throw new Error("UNKNOWN_SPEC_VERSION error not found");
    expect(c3Err.index).toBe(0);
    expect(c3Err.message).toContain("var/99.0");
  });

  test("C3: UNKNOWN_SPEC_VERSION does NOT also cause L1_INVALID (signature was valid)", async () => {
    const badManifest = createReceipt({
      ...specManifestFields("c3b-wf", 0, null),
      spec_version: "var/99.0" as "var/1.0",
    });
    const sm = await signReceipt(badManifest, privKey, KEY_ID);

    const result = await verifyChain([sm], pubKey);

    expect(result.valid).toBe(false);
    // UNKNOWN_SPEC_VERSION present
    expect(result.errors.some((e) => e.code === "UNKNOWN_SPEC_VERSION")).toBe(true);
    // L1_INVALID must NOT be present — signature was valid (covers the bad spec_version)
    expect(result.errors.some((e) => e.code === "L1_INVALID")).toBe(false);
  });

  // ── D1 ─────────────────────────────────────────────────────────────────────

  test("D1: action_receipt with billable_reason=DEGRADED_SESSION → PASS + DEGRADED_STATE warning", async () => {
    const sm = await signReceipt(createReceipt(specManifestFields("d1-wf", 0)), privKey, KEY_ID);
    // Build action_receipt with billable_reason=DEGRADED_SESSION
    const degradedAction = {
      ...specActionFields("d1-wf", 1),
      billable: true,
      billable_reason: "DEGRADED_SESSION",
    } as ReceiptFields;
    const sa = await signReceipt(chainReceipt(createReceipt(degradedAction), sm), privKey, KEY_ID);

    const result = await verifyChain([sm, sa], pubKey);

    // Chain is structurally valid — warnings do NOT affect valid
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);

    // D1 warning must be emitted
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0].code).toBe("DEGRADED_STATE");
    expect(result.warnings[0].index).toBe(1);
    expect(result.warnings[0].message).toContain("DEGRADED_SESSION");
  });

  test("D1: action_receipt with other billable_reason does NOT trigger DEGRADED_STATE warning", async () => {
    const sm = await signReceipt(createReceipt(specManifestFields("d1b-wf", 0)), privKey, KEY_ID);
    const normalAction = {
      ...specActionFields("d1b-wf", 1),
      billable: true,
      billable_reason: "MONEY_ACTION_ATTEMPT",
    } as ReceiptFields;
    const sa = await signReceipt(chainReceipt(createReceipt(normalAction), sm), privKey, KEY_ID);

    const result = await verifyChain([sm, sa], pubKey);
    expect(result.valid).toBe(true);
    expect(result.warnings.filter((w) => w.code === "DEGRADED_STATE")).toHaveLength(0);
  });

  // ── D2 ─────────────────────────────────────────────────────────────────────

  test("D2: post_receipt with action_receipt lacking money_action=true → PASS + MONEY_ACTION_TAG_MISSING warning", async () => {
    const sm = await signReceipt(createReceipt(specManifestFields("d2-wf", 0)), privKey, KEY_ID);
    // action_receipt WITHOUT money_action: true
    const sa = await signReceipt(
      chainReceipt(createReceipt(specActionFields("d2-wf", 1)), sm),
      privKey,
      KEY_ID
    );

    // post_receipt linked to the action_receipt above via pre_receipt_id
    const postFields: PostReceiptFields = {
      post_receipt_id: "d2-post-01",
      record_type: "post_receipt",
      spec_version: "var/1.0",
      pre_receipt_id: "spec-action-d2-wf-1",  // receipt_id of sa
      workflow_id: "d2-wf",
      agent_id: "spec-agent",
      sequence_number: 2,   // placeholder — chainReceipt will override
      prev_receipt_hash: "placeholder",  // placeholder — chainReceipt will override
      policy_bundle_hash: ZERO_HASH,
      tool_name: "bash",
      terminal_outcome: "SUCCESS",
      upstream_response_digest: null,
      projection_id: null,
      projection_hash: null,
      idempotency_key: null,
      tool_call_correlation_id: null,
      execution_start_ms: 0,
      execution_end_ms: 1,
      degraded_reason: null,
      billable: false,
      billable_reason: "READ_ONLY",
      issued_at: "2026-03-01T00:00:00Z",
      account_context: null,
      rfc3161_token: null,
      tsa_id: null,
    };
    const sp = await signReceipt(chainReceipt(createReceipt(postFields), sa), privKey, KEY_ID);

    const result = await verifyChain([sm, sa, sp], pubKey);

    // Chain is structurally valid — warnings do NOT affect valid
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);

    // D2 warning must be emitted
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0].code).toBe("MONEY_ACTION_TAG_MISSING");
    expect(result.warnings[0].index).toBe(2);  // post_receipt is at sorted index 2
    expect(result.warnings[0].message).toContain("spec-action-d2-wf-1");
  });

  test("D2: post_receipt with action_receipt that HAS money_action=true does NOT trigger warning", async () => {
    const sm = await signReceipt(createReceipt(specManifestFields("d2b-wf", 0)), privKey, KEY_ID);
    // action_receipt WITH money_action: true
    const moneyAction = {
      ...specActionFields("d2b-wf", 1),
      money_action: true,
    } as ReceiptFields;
    const sa = await signReceipt(chainReceipt(createReceipt(moneyAction), sm), privKey, KEY_ID);

    const postFields: PostReceiptFields = {
      post_receipt_id: "d2b-post-01",
      record_type: "post_receipt",
      spec_version: "var/1.0",
      pre_receipt_id: "spec-action-d2b-wf-1",  // receipt_id of sa
      workflow_id: "d2b-wf",
      agent_id: "spec-agent",
      sequence_number: 2,
      prev_receipt_hash: "placeholder",
      policy_bundle_hash: ZERO_HASH,
      tool_name: "bash",
      terminal_outcome: "SUCCESS",
      upstream_response_digest: null,
      projection_id: null,
      projection_hash: null,
      idempotency_key: null,
      tool_call_correlation_id: null,
      execution_start_ms: 0,
      execution_end_ms: 1,
      degraded_reason: null,
      billable: true,
      billable_reason: "MONEY_ACTION_ATTEMPT",
      issued_at: "2026-03-01T00:00:00Z",
      account_context: null,
      rfc3161_token: null,
      tsa_id: null,
    };
    const sp = await signReceipt(chainReceipt(createReceipt(postFields), sa), privKey, KEY_ID);

    const result = await verifyChain([sm, sa, sp], pubKey);
    expect(result.valid).toBe(true);
    expect(result.warnings.filter((w) => w.code === "MONEY_ACTION_TAG_MISSING")).toHaveLength(0);
  });

  test("verifyChain — empty chain returns empty warnings array", async () => {
    const result = await verifyChain([], pubKey);
    expect(result.warnings).toEqual([]);
  });
});
