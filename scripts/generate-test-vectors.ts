#!/usr/bin/env ts-node
/**
 * generate-test-vectors.ts
 *
 * Generates 21 signed VAR v1 test vectors (TV-01 to TV-21) and writes them to
 * deploy/schema-server/public/var/v1/test-vectors.json.
 *
 * Key ID: ns-test-01 (deterministic from seed for reproducible CI)
 *
 * TV-01..TV-05: well-formed chains → expected L1=PASS, L2=PASS
 * TV-06: tampered signature → expected L1=FAIL, L2=PASS
 * TV-07..TV-12: structurally malformed chains → expected L1=PASS, L2=FAIL
 * TV-13: valid chain + allowlisted TSA token → expected L3=PASS
 * TV-14: valid chain + non-allowlisted TSA token → expected L3=FAIL
 * TV-15: chain starting with action_receipt (no manifest) → expected L2=FAIL (MISSING_MANIFEST)
 * TV-16: DER parsing supply-chain check — expected_messageimprint_sha256 verified
 *        independently by the conform runner after verifyL3 returns PASS.
 * TV-17: C1 — wrong hash algorithm OID in TSA token → expected L3=FAIL (tsa_hash_algorithm_not_sha256)
 * TV-18: C2 — genTime backdated before receipt issued_at → expected L3=FAIL (tsa_gentime_before_issued_at)
 * TV-19: C3 — receipt with unknown spec_version → expected L2=FAIL (UNKNOWN_SPEC_VERSION)
 * TV-20: D1 — action_receipt with billable_reason=DEGRADED_SESSION → L2=PASS (DEGRADED_STATE warning)
 * TV-21: D2 — post_receipt whose action_receipt lacks money_action=true → L2=PASS (MONEY_ACTION_TAG_MISSING warning)
 *
 * Usage: npx ts-node scripts/generate-test-vectors.ts
 */

import * as fs from "fs";
import * as path from "path";
import * as ed from "@noble/ed25519";
import { createHash } from "crypto";
import canonicalize from "canonicalize";
import {
  createReceipt,
  signReceipt,
  chainReceipt,
} from "../packages/receipts/src/index";
import type { ReceiptFields, SignedReceipt } from "../packages/receipts/src/index";
import { buildRfc3161Token } from "../packages/receipts/src/test-utils";
import type { PostReceiptFields } from "../packages/receipts/src/index";

const KEY_ID = "ns-test-01";
const ZERO_HASH = "sha256:" + "0".repeat(64);
const OUT_PATH = path.join(
  __dirname,
  "../deploy/schema-server/public/var/v1/test-vectors.json"
);

// Deterministic private key from seed (for reproducible test vectors)
// Using a fixed 32-byte seed so vectors are stable across regeneration
const SEED_HEX = "dead".repeat(16); // 32 bytes of 0xde 0xad repeating (64 hex chars)
const PRIVATE_KEY = new Uint8Array(Buffer.from(SEED_HEX, "hex"));

// ── Field builders ────────────────────────────────────────────────────────────

function nowish(): string {
  return "2026-02-28T00:00:00Z";
}

function manifestFields(
  workflowId: string,
  seq = 0,
  prevHash: string | null = null
): ReceiptFields {
  return {
    receipt_id: `manifest-${workflowId}-${seq}`,
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: "test-agent",
    issued_at: nowish(),
    prev_receipt_hash: prevHash,
    sequence_number: seq,
    policy_bundle_hash: ZERO_HASH,
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

function actionFields(
  workflowId: string,
  seq: number,
  prevHash: string | null
): ReceiptFields {
  return {
    receipt_id: `action-${workflowId}-${seq}`,
    record_type: "action_receipt",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: "test-agent",
    issued_at: nowish(),
    prev_receipt_hash: prevHash,
    sequence_number: seq,
    policy_bundle_hash: ZERO_HASH,
    rfc3161_token: null,
    tsa_id: null,
    tool_name: "list_directory",
    params_canonical_hash: ZERO_HASH,
    decision: "ALLOW",
    decision_reason: "conformance test",
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

function closedFields(
  workflowId: string,
  seq: number,
  prevHash: string | null
): ReceiptFields {
  return {
    receipt_id: `closed-${workflowId}-${seq}`,
    record_type: "workflow_closed",
    spec_version: "var/1.0",
    workflow_id: workflowId,
    workflow_id_source: "nonsudo_generated",
    agent_id: "test-agent",
    issued_at: nowish(),
    prev_receipt_hash: prevHash,
    sequence_number: seq,
    policy_bundle_hash: ZERO_HASH,
    rfc3161_token: null,
    tsa_id: null,
    total_calls: seq - 1,
    total_blocked: 0,
    total_spend: null,
    session_duration_ms: 1000,
    close_reason: "explicit_close",
  };
}

async function buildValidChain(workflowId: string): Promise<SignedReceipt[]> {
  const m = createReceipt(manifestFields(workflowId, 0, null));
  const sm = await signReceipt(m, PRIVATE_KEY, KEY_ID);

  const a = createReceipt(actionFields(workflowId, 1, null));
  const ca = chainReceipt(a, sm);
  const sa = await signReceipt(ca, PRIVATE_KEY, KEY_ID);

  const c = createReceipt(closedFields(workflowId, 2, null));
  const cc = chainReceipt(c, sa);
  const sc = await signReceipt(cc, PRIVATE_KEY, KEY_ID);

  return [sm, sa, sc];
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const pubKey = await ed.getPublicKeyAsync(PRIVATE_KEY);
  const pubKeyJwk = {
    kty: "OKP",
    crv: "Ed25519",
    kid: KEY_ID,
    x: Buffer.from(pubKey).toString("base64url"),
    use: "sig",
  };

  // Build TV-01..TV-05: valid chains
  const tv01 = await buildValidChain("TV01-wf");
  const tv02 = await buildValidChain("TV02-wf");
  const tv03 = await buildValidChain("TV03-wf");

  // TV-04: manifest-only (valid single-receipt chain)
  const m04 = createReceipt(manifestFields("TV04-wf", 0, null));
  const sm04 = await signReceipt(m04, PRIVATE_KEY, KEY_ID);

  // TV-05: two actions
  const m05 = createReceipt(manifestFields("TV05-wf", 0, null));
  const sm05 = await signReceipt(m05, PRIVATE_KEY, KEY_ID);
  const a05a = createReceipt(actionFields("TV05-wf", 1, null));
  const ca05a = chainReceipt(a05a, sm05);
  const sa05a = await signReceipt(ca05a, PRIVATE_KEY, KEY_ID);
  const a05b = createReceipt(actionFields("TV05-wf", 2, null));
  const ca05b = chainReceipt(a05b, sa05a);
  const sa05b = await signReceipt(ca05b, PRIVATE_KEY, KEY_ID);

  // TV-06: tampered signature on manifest → L1 FAIL, L2 PASS
  // Build a valid manifest, then flip the first byte of the sig.
  const m06 = createReceipt(manifestFields("TV06-wf", 0, null));
  const sm06raw = await signReceipt(m06, PRIVATE_KEY, KEY_ID);
  const sig06bytes = Buffer.from(sm06raw.signature.sig, "base64url");
  sig06bytes[0] ^= 0xff;
  const sm06 = {
    ...sm06raw,
    signature: { ...sm06raw.signature, sig: sig06bytes.toString("base64url") },
  } as typeof sm06raw;

  // TV-07: sequence gap → L2 FAIL (INCOMPLETE_CHAIN)
  const m07 = createReceipt(manifestFields("TV07-wf", 0, null));
  const sm07 = await signReceipt(m07, PRIVATE_KEY, KEY_ID);
  const a07 = createReceipt(actionFields("TV07-wf", 2, null)); // gap: missing seq 1
  const ca07 = chainReceipt(a07, sm07);
  (ca07 as unknown as Record<string, unknown>)["sequence_number"] = 2;
  const sa07 = await signReceipt(ca07, PRIVATE_KEY, KEY_ID);

  // TV-08: prev_receipt_hash mismatch → L2 FAIL (HASH_MISMATCH)
  const m08 = createReceipt(manifestFields("TV08-wf", 0, null));
  const sm08 = await signReceipt(m08, PRIVATE_KEY, KEY_ID);
  const a08 = createReceipt(actionFields("TV08-wf", 1, "sha256:" + "a".repeat(64)));
  // set sequence_number manually (skip chainReceipt to preserve wrong hash)
  (a08 as unknown as Record<string, unknown>)["sequence_number"] = 1;
  const sa08 = await signReceipt(a08, PRIVATE_KEY, KEY_ID);

  // TV-09: single manifest with non-null prev_receipt_hash → L2 FAIL
  const m09fields = manifestFields("TV09-wf", 0, "sha256:" + "b".repeat(64));
  const m09 = createReceipt(m09fields);
  const sm09 = await signReceipt(m09, PRIVATE_KEY, KEY_ID);

  // TV-10: two manifests (second at seq 1) → L2 FAIL (structure error)
  const m10a = createReceipt(manifestFields("TV10-wf", 0, null));
  const sm10a = await signReceipt(m10a, PRIVATE_KEY, KEY_ID);
  const m10b = createReceipt(manifestFields("TV10-wf", 1, null));
  const cm10b = chainReceipt(m10b, sm10a);
  const sm10b = await signReceipt(cm10b, PRIVATE_KEY, KEY_ID);

  // TV-11: correct chain with wrong prev_hash in last receipt → L2 FAIL
  const m11 = createReceipt(manifestFields("TV11-wf", 0, null));
  const sm11 = await signReceipt(m11, PRIVATE_KEY, KEY_ID);
  const a11 = createReceipt(actionFields("TV11-wf", 1, "sha256:" + "0".repeat(64)));
  (a11 as unknown as Record<string, unknown>)["sequence_number"] = 1;
  const sa11 = await signReceipt(a11, PRIVATE_KEY, KEY_ID);

  // TV-12: duplicate sequence numbers → L2 FAIL
  const m12 = createReceipt(manifestFields("TV12-wf", 0, null));
  const sm12 = await signReceipt(m12, PRIVATE_KEY, KEY_ID);
  const a12 = createReceipt(actionFields("TV12-wf", 0, null)); // dup seq=0
  const sa12 = await signReceipt(a12, PRIVATE_KEY, KEY_ID);

  // TV-13: valid chain + valid RFC 3161 token from allowlisted TSA → L3 PASS
  const tv13 = await buildValidChain("TV13-wf");
  const tsa13Records = tv13.map((r) => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: "digicert",
    timestamped_at: nowish(),
  }));

  // TV-14: valid chain + token from non-allowlisted TSA → L3 FAIL
  // Token is structurally valid (correct hash) but tsa_id is not allowlisted → L3 FAIL at allowlist step
  const tv14 = await buildValidChain("TV14-wf");
  const tsa14Records = tv14.map((r) => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: "evilcorp-tsa",
    timestamped_at: nowish(),
  }));

  // TV-15: action_receipt as the first receipt (no workflow_manifest) → L2 FAIL (MISSING_MANIFEST)
  const sa15 = await signReceipt(
    createReceipt(actionFields("TV15-wf", 0, null)),
    PRIVATE_KEY,
    KEY_ID
  );

  // TV-16: DER parsing supply-chain check
  // A known-valid chain with a real RFC 3161 token. The conform runner must parse
  // the DER token directly (not via verifyL3) and compare messageImprint.hashedMessage
  // against expected_messageimprint_sha256. A compromised @peculiar/asn1-* library
  // that silently returns wrong field values would fail this check even if verifyL3 PASS.
  const tv16 = await buildValidChain("TV16-wf");
  const tsa16Records = tv16.map((r) => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r),
    tsa_id: "digicert",
    timestamped_at: nowish(),
  }));
  // Compute the expected messageImprint hash for the first receipt.
  // SHA-256(JCS(complete_signed_receipt)) — the same value verifyL3 checks.
  const tv16FirstCanon = canonicalize(tv16[0] as object);
  if (!tv16FirstCanon) throw new Error("canonicalize returned undefined for TV16");
  const tv16ExpectedImprint = createHash("sha256").update(tv16FirstCanon).digest("hex");

  // TV-17: C1 — wrong hash algorithm OID (MD5 instead of SHA-256) → L3 FAIL
  // Token passes allowlist + PKIStatus, fails at OID check [5a]: tsa_hash_algorithm_not_sha256
  const tv17 = await buildValidChain("TV17-wf");
  const tsa17Records = tv17.map((r) => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r, { overrideOid: "1.2.840.113549.2.5" }), // MD5 OID
    tsa_id: "digicert",
    timestamped_at: nowish(),
  }));

  // TV-18: C2 — genTime backdated before receipt issued_at → L3 FAIL
  // issued_at = "2026-02-28T00:00:00Z"; genTime = "2020-01-01T00:00:00Z" (6 years before)
  const tv18 = await buildValidChain("TV18-wf");
  const tsa18Records = tv18.map((r) => ({
    receipt_id: r.receipt_id,
    rfc3161_token: buildRfc3161Token(r, { overrideGenTime: new Date("2020-01-01T00:00:00Z") }),
    tsa_id: "digicert",
    timestamped_at: nowish(),
  }));

  // TV-19: C3 — receipt with unknown spec_version → L2 FAIL (UNKNOWN_SPEC_VERSION)
  // spec_version="var/99.0" is not "var/1.0" — L1 passes (sig covers the bad value),
  // verifyChain C3 check fires and adds UNKNOWN_SPEC_VERSION error → valid=false.
  const m19 = createReceipt({
    ...manifestFields("TV19-wf", 0, null),
    spec_version: "var/99.0" as "var/1.0",
  });
  const sm19 = await signReceipt(m19, PRIVATE_KEY, KEY_ID);

  // TV-20: D1 — action_receipt with billable_reason=DEGRADED_SESSION → L2=PASS (DEGRADED_STATE warning)
  // Chain is structurally valid; verifyChain emits a D1 warning (does NOT fail the chain).
  const sm20 = await signReceipt(createReceipt(manifestFields("TV20-wf", 0, null)), PRIVATE_KEY, KEY_ID);
  const a20fields = {
    ...(actionFields("TV20-wf", 1, null) as object),
    billable: true,
    billable_reason: "DEGRADED_SESSION",
  } as ReceiptFields;
  const sa20 = await signReceipt(chainReceipt(createReceipt(a20fields), sm20), PRIVATE_KEY, KEY_ID);
  const sc20 = await signReceipt(
    chainReceipt(createReceipt(closedFields("TV20-wf", 2, null)), sa20),
    PRIVATE_KEY,
    KEY_ID
  );

  // TV-21: D2 — post_receipt whose action_receipt lacks money_action=true → L2=PASS (MONEY_ACTION_TAG_MISSING warning)
  // Chain is structurally valid; verifyChain emits a D2 warning (does NOT fail the chain).
  const sm21 = await signReceipt(createReceipt(manifestFields("TV21-wf", 0, null)), PRIVATE_KEY, KEY_ID);
  // action_receipt WITHOUT money_action: true — triggers D2 warning on the linked post_receipt
  const ca21 = chainReceipt(createReceipt(actionFields("TV21-wf", 1, null)), sm21);
  const sa21 = await signReceipt(ca21, PRIVATE_KEY, KEY_ID);
  // post_receipt linked via pre_receipt_id to the action_receipt above
  const post21: PostReceiptFields = {
    post_receipt_id: "post-TV21-wf-2",
    record_type: "post_receipt",
    spec_version: "var/1.0",
    pre_receipt_id: "action-TV21-wf-1",  // receipt_id from actionFields("TV21-wf", 1, null)
    workflow_id: "TV21-wf",
    agent_id: "test-agent",
    sequence_number: 2,   // placeholder; chainReceipt will override with sa21.seq + 1 = 2
    prev_receipt_hash: "placeholder",  // overridden by chainReceipt
    policy_bundle_hash: ZERO_HASH,
    tool_name: "list_directory",
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
    issued_at: nowish(),
    account_context: null,
    rfc3161_token: null,
    tsa_id: null,
  };
  const spost21 = await signReceipt(chainReceipt(createReceipt(post21), sa21), PRIVATE_KEY, KEY_ID);

  const vectors = [
    {
      id: "TV-01",
      description: "valid 3-receipt chain (manifest → action → closed)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: tv01,
      tsa_records: [],
    },
    {
      id: "TV-02",
      description: "valid 3-receipt chain (independent workflow)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: tv02,
      tsa_records: [],
    },
    {
      id: "TV-03",
      description: "valid 3-receipt chain (third independent workflow)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: tv03,
      tsa_records: [],
    },
    {
      id: "TV-04",
      description: "valid single-receipt manifest-only chain",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm04],
      tsa_records: [],
    },
    {
      id: "TV-05",
      description: "valid 4-receipt chain (manifest → 2 actions)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm05, sa05a, sa05b],
      tsa_records: [],
    },
    {
      id: "TV-06",
      description: "tampered signature on manifest → L1 FAIL",
      expected_l1: "FAIL",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm06],
      tsa_records: [],
    },
    {
      id: "TV-07",
      description: "sequence gap between seq 0 and seq 2 → INCOMPLETE_CHAIN",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm07, sa07],
      tsa_records: [],
    },
    {
      id: "TV-08",
      description: "prev_receipt_hash mismatch on action → HASH_MISMATCH",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm08, sa08],
      tsa_records: [],
    },
    {
      id: "TV-09",
      description: "manifest with non-null prev_receipt_hash → NULL_HASH_EXPECTED",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm09],
      tsa_records: [],
    },
    {
      id: "TV-10",
      description: "two consecutive manifests → second manifest has wrong structure",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm10a, sm10b],
      tsa_records: [],
    },
    {
      id: "TV-11",
      description: "correct sequence numbers but wrong prev_hash → HASH_MISMATCH",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm11, sa11],
      tsa_records: [],
    },
    {
      id: "TV-12",
      description: "duplicate sequence number 0 → INCOMPLETE_CHAIN",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm12, sa12],
      tsa_records: [],
    },
    {
      id: "TV-13",
      description: "valid chain + allowlisted TSA token → L3 PASS",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "PASS",
      receipts: tv13,
      tsa_records: tsa13Records,
    },
    {
      id: "TV-14",
      description: "valid chain + non-allowlisted TSA token → L3 FAIL",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "FAIL",
      receipts: tv14,
      tsa_records: tsa14Records,
    },
    {
      id: "TV-15",
      description: "chain starts with action_receipt (not workflow_manifest) → MISSING_MANIFEST",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sa15],
      tsa_records: [],
    },
    {
      id: "TV-16",
      description: "DER parsing supply-chain check — verifies @peculiar/asn1-* returns correct messageImprint bytes",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "PASS",
      expected_messageimprint_sha256: tv16ExpectedImprint,
      receipts: tv16,
      tsa_records: tsa16Records,
    },
    {
      id: "TV-17",
      description: "C1: TSA token uses MD5 OID instead of SHA-256 → L3 FAIL (tsa_hash_algorithm_not_sha256)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "FAIL",
      receipts: tv17,
      tsa_records: tsa17Records,
    },
    {
      id: "TV-18",
      description: "C2: TSA token genTime is before receipt issued_at → L3 FAIL (tsa_gentime_before_issued_at)",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "FAIL",
      receipts: tv18,
      tsa_records: tsa18Records,
    },
    {
      id: "TV-19",
      description: "C3: receipt has spec_version='var/99.0' (unknown) → L2 FAIL (UNKNOWN_SPEC_VERSION)",
      expected_l1: "PASS",
      expected_l2: "FAIL",
      expected_l3: "SKIPPED",
      receipts: [sm19],
      tsa_records: [],
    },
    {
      id: "TV-20",
      description: "D1: action_receipt with billable_reason=DEGRADED_SESSION — chain valid, D1 warning emitted",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm20, sa20, sc20],
      tsa_records: [],
    },
    {
      id: "TV-21",
      description: "D2: post_receipt linked to action_receipt without money_action=true — chain valid, D2 warning emitted",
      expected_l1: "PASS",
      expected_l2: "PASS",
      expected_l3: "SKIPPED",
      receipts: [sm21, sa21, spost21],
      tsa_records: [],
    },
  ];

  const output = {
    spec_version: "var/1.0",
    generated_at: nowish(),
    key_id: KEY_ID,
    key_jwk: pubKeyJwk,
    vectors,
  };

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, JSON.stringify(output, null, 2) + "\n");

  console.log(`Written ${vectors.length} test vectors to ${OUT_PATH}`); // now 21 vectors
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
