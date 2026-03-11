/**
 * L3 regression tests — verifyL3 DER validation (Fix 1) + C1/C2 spec checks.
 *
 * L3-01: valid DER token with correct messageImprint → PASS
 * L3-02: valid DER token but messageImprint hash is for a different receipt → FAIL "tsa_messageimprint_mismatch"
 * L3-03: rfc3161_token is not valid DER (garbage bytes) → FAIL "tsa_der_parse_error"
 * L3-04: tsa_id not in accepting_tsa_ids → FAIL "tsa_not_in_allowlist"
 * L3-05: no sidecar entry for any receipt → SKIPPED
 * C1: TSA token uses non-SHA-256 OID → FAIL "tsa_hash_algorithm_not_sha256"
 * C2: TSA token genTime is before receipt issued_at → FAIL "tsa_gentime_before_issued_at"
 */

import { createReceipt, signReceipt, verifyL3 } from "../index";
import type { WorkflowManifestFields, SignedWorkflowManifest, TsaRecord } from "../types";
import { buildRfc3161Token } from "../test-utils";

// Fixed key for deterministic tests
const SEED_HEX = "babe".repeat(16);
const PRIVATE_KEY = new Uint8Array(Buffer.from(SEED_HEX, "hex"));
const KEY_ID = "test-l3-key";

function makeManifestFields(): WorkflowManifestFields {
  return {
    receipt_id: "01L3TEST000000000000001",
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: "01L3TEST000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "test-agent",
    issued_at: "2026-02-28T00:00:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: "sha256:" + "0".repeat(64),
    rfc3161_token: null,
    tsa_id: null,
    initiator_id: "test-init",
    workflow_owner: "test-team",
    session_budget: { api_calls: 100 },
    declared_tools: [],
    capability_manifest_hash: null,
    parent_workflow_id: null,
    framework_ref: null,
  };
}

async function makeSignedManifest(): Promise<SignedWorkflowManifest> {
  const m = createReceipt(makeManifestFields());
  return signReceipt(m, PRIVATE_KEY, KEY_ID) as Promise<SignedWorkflowManifest>;
}

// ── L3-01 ──────────────────────────────────────────────────────────────────────

test("L3-01: valid DER token with correct messageImprint → PASS", async () => {
  const receipt = await makeSignedManifest();
  const token = buildRfc3161Token(receipt);

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: token,
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("PASS");
  expect(result.reason).toBeUndefined();
});

// ── L3-02 ──────────────────────────────────────────────────────────────────────

test("L3-02: valid DER token but messageImprint is for a different receipt → FAIL tsa_messageimprint_mismatch", async () => {
  const receipt = await makeSignedManifest();

  // Build a second distinct receipt — its token will have a different hash
  const fields2 = makeManifestFields();
  fields2.receipt_id = "01L3TEST000000000000002";
  fields2.workflow_id = "01L3TEST000000000000099";
  const receipt2 = await signReceipt(createReceipt(fields2), PRIVATE_KEY, KEY_ID);

  // Token is for receipt2 but we serve it for receipt
  const wrongToken = buildRfc3161Token(receipt2);

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: wrongToken,
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("FAIL");
  expect(result.reason).toBe("tsa_messageimprint_mismatch");
  expect(result.failed_receipt_id).toBe(receipt.receipt_id);
});

// ── L3-03 ──────────────────────────────────────────────────────────────────────

test("L3-03: rfc3161_token is garbage bytes → FAIL tsa_der_parse_error", async () => {
  const receipt = await makeSignedManifest();

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: Buffer.from("not-valid-der-at-all!!!!").toString("base64"),
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("FAIL");
  expect(result.reason).toBe("tsa_der_parse_error");
  expect(result.failed_receipt_id).toBe(receipt.receipt_id);
});

// ── L3-04 ──────────────────────────────────────────────────────────────────────

test("L3-04: tsa_id not in accepting_tsa_ids → FAIL tsa_not_in_allowlist", async () => {
  const receipt = await makeSignedManifest();
  const token = buildRfc3161Token(receipt);

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: token,
      tsa_id: "evilcorp-tsa",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  // Default allowlist does not include "evilcorp-tsa"
  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("FAIL");
  expect(result.reason).toBe("tsa_not_in_allowlist");
  expect(result.failed_receipt_id).toBe(receipt.receipt_id);
});

// ── L3-05 ──────────────────────────────────────────────────────────────────────

test("L3-05: no sidecar entry for any receipt → SKIPPED", async () => {
  const receipt = await makeSignedManifest();

  // Empty sidecar — no TSA records
  const result = await verifyL3([receipt], []);
  expect(result.status).toBe("SKIPPED");
  expect(result.reason).toBeUndefined();
});

// ── C1 ─────────────────────────────────────────────────────────────────────────

test("C1: TSA token with MD5 OID (not SHA-256) → FAIL tsa_hash_algorithm_not_sha256", async () => {
  const receipt = await makeSignedManifest();
  // MD5 OID: "1.2.840.113549.2.5" — not SHA-256
  const token = buildRfc3161Token(receipt, { overrideOid: "1.2.840.113549.2.5" });

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: token,
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("FAIL");
  expect(result.reason).toBe("tsa_hash_algorithm_not_sha256");
  expect(result.failed_receipt_id).toBe(receipt.receipt_id);
});

// ── C2 ─────────────────────────────────────────────────────────────────────────

test("C2: TSA token genTime before receipt issued_at → FAIL tsa_gentime_before_issued_at", async () => {
  const receipt = await makeSignedManifest();
  // receipt.issued_at = "2026-02-28T00:00:00Z"; genTime set to 2020 (6 years before)
  const token = buildRfc3161Token(receipt, { overrideGenTime: new Date("2020-01-01T00:00:00Z") });

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: token,
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("FAIL");
  expect(result.reason).toBe("tsa_gentime_before_issued_at");
  expect(result.failed_receipt_id).toBe(receipt.receipt_id);
});

// ── C2b: genTime exactly equal to issued_at is accepted ────────────────────────

test("C2b: TSA token genTime exactly equal to issued_at → PASS (boundary: genTime >= issued_at)", async () => {
  const receipt = await makeSignedManifest();
  // issued_at = "2026-02-28T00:00:00Z" — set genTime to exactly the same moment
  const token = buildRfc3161Token(receipt, { overrideGenTime: new Date("2026-02-28T00:00:00Z") });

  const tsaRecords: TsaRecord[] = [
    {
      receipt_id: receipt.receipt_id,
      rfc3161_token: token,
      tsa_id: "digicert",
      timestamped_at: "2026-02-28T00:00:00Z",
    },
  ];

  const result = await verifyL3([receipt], tsaRecords);
  expect(result.status).toBe("PASS");
});
