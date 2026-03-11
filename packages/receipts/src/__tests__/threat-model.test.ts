/**
 * Threat-model gap tests — TM-1 through TM-5, TM-8
 *
 * These tests verify that specific attack scenarios are mitigated by the
 * VAR v1.0 signing and chain-verification implementation. A test is
 * considered "covered" only when it would FAIL if the mitigation were removed.
 *
 * TM-1 : Per-field tamper — each action_receipt field category is individually tested
 * TM-2 : Null/missing signature block — verifySignature returns L1 FAIL, never throws
 * TM-3 : Chain extension with a different key — L1_INVALID on the forged receipt
 * TM-5 : Hash-reference swap — A.prev=hash(B), B.prev=hash(manifest) → HASH_MISMATCH
 * TM-8 : Decision field tampering (BLOCK→ALLOW) — covered by TM-1a
 */

import { createHash } from "crypto";
import { createReceipt, signReceipt, chainReceipt, verifySignature, verifyChain } from "../index";
import type { ReceiptFields, SignedReceipt } from "../types";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeManifestFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "TM0000000000000000000001",
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: "TM0000000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-tm-test",
    issued_at: "2026-03-01T10:00:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: "sha256:" + "0".repeat(64),
    rfc3161_token: null,
    tsa_id: null,
    initiator_id: "tm-test-user",
    workflow_owner: "tm-team",
    session_budget: { api_calls: 100 },
    declared_tools: ["bash"],
    capability_manifest_hash: null,
    parent_workflow_id: null,
    framework_ref: null,
    ...overrides,
  } as ReceiptFields;
}

function makeActionFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "TM0000000000000000000002",
    record_type: "action_receipt",
    spec_version: "var/1.0",
    workflow_id: "TM0000000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-tm-test",
    issued_at: "2026-03-01T10:00:01Z",
    prev_receipt_hash: "sha256:" + "0".repeat(64),
    sequence_number: 1,
    policy_bundle_hash: "sha256:" + "0".repeat(64),
    rfc3161_token: null,
    tsa_id: null,
    tool_name: "bash",
    params_canonical_hash: "sha256:" + "a".repeat(64),
    decision: "BLOCK",
    decision_reason: "policy blocked this tool",
    decision_order: 1,
    queue_status: "COMPLETED",
    queue_timeout_ms: 5000,
    blast_radius: "HIGH",
    reversible: false,
    state_version_before: 0,
    state_version_after: 1,
    response_hash: null,
    ...overrides,
  } as ReceiptFields;
}

function sha256ofReceipt(receipt: SignedReceipt): string {
  const canonical = canonicalize(receipt as object);
  if (!canonical) throw new Error("canonicalize returned undefined");
  return "sha256:" + createHash("sha256").update(canonical).digest("hex");
}

// ── TM-1: Per-field tamper ────────────────────────────────────────────────────

describe("TM-1 / TM-8: Per-field tamper — each field category fails verifySignature", () => {
  let privKey: Uint8Array;
  let pubKey: Uint8Array;

  beforeAll(async () => {
    privKey = ed.utils.randomPrivateKey();
    pubKey = await ed.getPublicKeyAsync(privKey);
  });

  // TM-1a / TM-8: Tampering `decision` from BLOCK to ALLOW invalidates L1.
  // This is the critical field: an attacker who replaces BLOCK→ALLOW on a signed
  // receipt must NOT be able to produce a valid audit trail.
  test("TM-1a / TM-8: tamper decision BLOCK→ALLOW → L1 FAIL", async () => {
    const unsigned = createReceipt(makeActionFields({ decision: "BLOCK" }));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, decision: "ALLOW" } as unknown as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/invalid|fail/i);
  });

  // TM-1b: Tampering `tool_name` invalidates L1.
  test("TM-1b: tamper tool_name bash→rm_rf → L1 FAIL", async () => {
    const unsigned = createReceipt(makeActionFields({ tool_name: "bash" }));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, tool_name: "rm_rf" } as unknown as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);

    expect(result.valid).toBe(false);
  });

  // TM-1c: Tampering `params_canonical_hash` invalidates L1.
  // An attacker changing the hash to hide what params were used must fail.
  test("TM-1c: tamper params_canonical_hash → L1 FAIL", async () => {
    const unsigned = createReceipt(makeActionFields({
      params_canonical_hash: "sha256:" + "a".repeat(64),
    }));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = {
      ...signed,
      params_canonical_hash: "sha256:" + "0".repeat(64),
    } as unknown as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);

    expect(result.valid).toBe(false);
  });

  // TM-1d: Tampering `sequence_number` invalidates L1.
  // An attacker cannot reorder a receipt in the chain by changing its seq number
  // without invalidating the signature.
  test("TM-1d: tamper sequence_number 1→99 → L1 FAIL", async () => {
    const unsigned = createReceipt(makeActionFields({ sequence_number: 1 }));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, sequence_number: 99 } as unknown as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);

    expect(result.valid).toBe(false);
  });
});

// ── TM-2: Null / missing signature block ──────────────────────────────────────

describe("TM-2: null/undefined signature block → valid:false, no unhandled exception", () => {
  test("TM-2a: receipt.signature=null → { valid:false }, no throw", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeManifestFields());
    const signed = await signReceipt(unsigned, privKey);

    // Cast away TypeScript types to simulate a receipt with missing signature
    // (could arrive from untrusted NDJSON file or serialization bug)
    const nullSig = { ...signed, signature: null } as unknown as SignedReceipt;
    // Must return L1 FAIL — NOT throw TypeError
    const result = await verifySignature(nullSig, pubKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/missing signature/i);
  });

  test("TM-2b: receipt.signature=undefined → { valid:false }, no throw", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeManifestFields());
    const signed = await signReceipt(unsigned, privKey);

    const { signature: _sig, ...noSig } = signed as SignedReceipt & { signature: unknown };
    void _sig;
    const result = await verifySignature(noSig as unknown as SignedReceipt, pubKey);
    expect(result.valid).toBe(false);
  });
});

// ── TM-3: Chain extension with different key ──────────────────────────────────

describe("TM-3: chain extension — new receipt signed with a different key → L1_INVALID", () => {
  test("TM-3: 2-receipt chain (key A) + attacker appends with key B → L1_INVALID at index 2", async () => {
    const keyA = ed.utils.randomPrivateKey();
    const pubKeyA = await ed.getPublicKeyAsync(keyA);

    const keyB = ed.utils.randomPrivateKey(); // attacker's key

    // Build legitimate chain with key A
    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, keyA);

    const actionFields = makeActionFields({ sequence_number: 1, receipt_id: "TM0000000000000000000010" });
    const chainedAction = chainReceipt(createReceipt(actionFields), signedManifest);
    const signedAction = await signReceipt(chainedAction, keyA);

    // Attacker appends a receipt signed with key B but using the correct prev_receipt_hash
    const evilFields = makeActionFields({ sequence_number: 2, receipt_id: "TM0000000000000000000011" });
    const evilChained = chainReceipt(createReceipt(evilFields), signedAction);
    // Signed with attacker's key B — NOT key A
    const evilSigned = await signReceipt(evilChained, keyB);

    // verifyChain with key A must reject the forged receipt
    const result = await verifyChain([signedManifest, signedAction, evilSigned], pubKeyA);

    expect(result.valid).toBe(false);
    // The forged receipt (index 2) must fail L1
    const l1Error = result.errors.find((e) => e.code === "L1_INVALID" && e.index === 2);
    expect(l1Error).toBeDefined();
  });
});

// ── TM-5: Hash-reference swap ─────────────────────────────────────────────────

describe("TM-5: hash-reference swap — A.prev=hash(B), B.prev=hash(manifest) → HASH_MISMATCH", () => {
  test("TM-5: swapped prev_receipt_hash references (valid sigs, wrong links) → HASH_MISMATCH", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    // Build manifest
    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);
    const hashManifest = sha256ofReceipt(signedManifest);

    // Build B (seq=2) with prev = hash(manifest)
    // This receipt is legitimately signed but the prev_hash is wrong for a seq=2 receipt
    const bFields = makeActionFields({
      receipt_id: "TM000000000000000000B002",
      sequence_number: 2,
    });
    const bUnsigned = createReceipt(bFields);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (bUnsigned as any).prev_receipt_hash = hashManifest;
    const signedB = await signReceipt(bUnsigned, privKey);
    const hashB = sha256ofReceipt(signedB);

    // Build A (seq=1) with prev = hash(B) — deliberate swap
    // A.prev should point to manifest, but is made to point to B
    const aFields = makeActionFields({
      receipt_id: "TM000000000000000000A001",
      sequence_number: 1,
    });
    const aUnsigned = createReceipt(aFields);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (aUnsigned as any).prev_receipt_hash = hashB;
    const signedA = await signReceipt(aUnsigned, privKey);

    // verifyChain sorts by seq: [manifest(0), A(1), B(2)]
    // Checks: A.prev == hash(manifest)? → NO (A.prev = hash(B)) → HASH_MISMATCH
    const result = await verifyChain([signedManifest, signedA, signedB], pubKey);

    expect(result.valid).toBe(false);
    const hashMismatch = result.errors.find((e) => e.code === "HASH_MISMATCH");
    expect(hashMismatch).toBeDefined();
  });
});
