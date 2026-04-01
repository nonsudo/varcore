import { createReceipt, signReceipt, verifySignature } from "../index";
import { ReceiptFields, SignedReceipt } from "../types";
import * as ed from "@noble/ed25519";

// Mandate continuity field overrides for testing
const MANDATE_FIELDS = {
  agent_class_id: "cls_abcdef1234567890abcdef1234567890",
  mandate_id: "mandate-payments-v1",
  mandate_version: "v1.0.0",
  chain_sequence: 0,
};

function makeActionFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "01HXYZ000000000000000002",
    record_type: "action_receipt",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-abc123",
    issued_at: "2026-02-28T10:00:01Z",
    prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    sequence_number: 1,
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    rfc3161_token: null,
    tsa_id: null,
    tool_name: "bash",
    params_canonical_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    decision: "ALLOW",
    decision_reason: "Policy allows this tool",
    decision_order: 1,
    queue_status: "COMPLETED",
    queue_timeout_ms: 5000,
    blast_radius: "LOW",
    reversible: true,
    state_version_before: 1,
    state_version_after: 2,
    response_hash: null,
    ...overrides,
  } as ReceiptFields;
}

function makeBudgetWarningFields(overrides: Record<string, unknown> = {}): ReceiptFields {
  return {
    budget_warning_id: "01HXYZ000000000000000010",
    record_type: "budget_warning",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    agent_id: "agent-abc123",
    sequence_number: 3,
    prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    tool_name: "stripe.createCharge",
    spent: 9000,
    reserved: 500,
    cap: 10000,
    threshold_pct: 90,
    issued_at: "2026-02-28T10:02:00Z",
    rfc3161_token: null,
    tsa_id: null,
    ...overrides,
  } as ReceiptFields;
}

describe("Mandate continuity fields — action_receipt (base type)", () => {
  test("action_receipt with mandate fields signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBe(MANDATE_FIELDS.agent_class_id);
    expect(signed.mandate_id).toBe(MANDATE_FIELDS.mandate_id);
    expect(signed.mandate_version).toBe(MANDATE_FIELDS.mandate_version);
    expect(signed.chain_sequence).toBe(MANDATE_FIELDS.chain_sequence);

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });

  test("tampering agent_class_id invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, agent_class_id: "cls_00000000000000000000000000000000" } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("tampering mandate_id invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, mandate_id: "mandate-evil" } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("action_receipt without mandate fields still signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields());
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBeUndefined();
    expect(signed.mandate_id).toBeUndefined();

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });
});

describe("Mandate continuity fields — budget_warning (non-base type)", () => {
  test("budget_warning with mandate fields signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBe(MANDATE_FIELDS.agent_class_id);
    expect(signed.mandate_id).toBe(MANDATE_FIELDS.mandate_id);
    expect(signed.mandate_version).toBe(MANDATE_FIELDS.mandate_version);
    expect(signed.chain_sequence).toBe(MANDATE_FIELDS.chain_sequence);

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });

  test("tampering chain_sequence on budget_warning invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, chain_sequence: 999 } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("budget_warning without mandate fields still signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields());
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBeUndefined();
    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });
});
