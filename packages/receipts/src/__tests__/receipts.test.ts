import { createReceipt, signReceipt, chainReceipt, verifySignature, verifyChain } from "../index";
import { ReceiptFields, SignedReceipt, SignedWorkflowManifest, SignedActionReceipt, SignedWorkflowClosed } from "../types";
import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";

// Helpers to build minimal valid field sets
function makeManifestFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "01HXYZ000000000000000001",
    record_type: "workflow_manifest",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-abc123",
    issued_at: "2026-02-28T10:00:00Z",
    prev_receipt_hash: null,
    sequence_number: 0,
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    rfc3161_token: null,
    tsa_id: null,
    initiator_id: "user@example.com",
    workflow_owner: "team-alpha",
    session_budget: { api_calls: 100, steps: 50 },
    declared_tools: ["bash", "read_file"],
    capability_manifest_hash: null,
    parent_workflow_id: null,
    framework_ref: null,
    ...overrides,
  } as ReceiptFields;
}

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

function makeClosedFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "01HXYZ000000000000000003",
    record_type: "workflow_closed",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-abc123",
    issued_at: "2026-02-28T10:01:00Z",
    prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    sequence_number: 2,
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    rfc3161_token: null,
    tsa_id: null,
    total_calls: 1,
    total_blocked: 0,
    total_spend: null,
    session_duration_ms: 60000,
    close_reason: "connection_teardown",
    ...overrides,
  } as ReceiptFields;
}

describe("1. createReceipt produces correct field structure for each record_type", () => {
  test("workflow_manifest has correct base fields and manifest-specific fields", () => {
    const fields = makeManifestFields();
    const receipt = createReceipt(fields);

    expect(receipt.record_type).toBe("workflow_manifest");
    expect(receipt.spec_version).toBe("var/1.0");
    expect(receipt.sequence_number).toBe(0);
    expect(receipt.prev_receipt_hash).toBeNull();
    expect(receipt.rfc3161_token).toBeNull();
    expect(receipt.tsa_id).toBeNull();

    // manifest-specific fields
    const m = receipt as unknown as SignedWorkflowManifest;
    expect(m.initiator_id).toBe("user@example.com");
    expect(m.workflow_owner).toBe("team-alpha");
    expect(m.declared_tools).toEqual(["bash", "read_file"]);
    expect(m.parent_workflow_id).toBeNull();
    expect(m.framework_ref).toBeNull();

    // no signature on unsigned receipt
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- testing that unsigned receipt has no signature field
    expect((receipt as any).signature).toBeUndefined();
  });

  test("action_receipt has correct fields", () => {
    const fields = makeActionFields();
    const receipt = createReceipt(fields);

    expect(receipt.record_type).toBe("action_receipt");
    const a = receipt as unknown as SignedActionReceipt;
    expect(a.tool_name).toBe("bash");
    expect(a.decision).toBe("ALLOW");
    expect(a.queue_status).toBe("COMPLETED");
    expect(a.blast_radius).toBe("LOW");
    expect(a.response_hash).toBeNull(); // always null at signing time
    expect(a.reversible).toBe(true);
  });

  test("workflow_closed has correct fields", () => {
    const fields = makeClosedFields();
    const receipt = createReceipt(fields);

    expect(receipt.record_type).toBe("workflow_closed");
    const c = receipt as unknown as SignedWorkflowClosed;
    expect(c.total_calls).toBe(1);
    expect(c.total_blocked).toBe(0);
    expect(c.close_reason).toBe("connection_teardown");
    expect(c.total_spend).toBeNull();
  });
});

describe("2. signReceipt produces a signature that verifySignature accepts", () => {
  test("sign and verify round-trip succeeds", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeManifestFields());
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.signature).toBeDefined();
    expect(signed.signature.alg).toBe("Ed25519");
    expect(signed.signature.key_id).toBeDefined();
    expect(signed.signature.sig).toBeDefined();
    // base64url: no padding, no +/ chars
    expect(signed.signature.sig).toMatch(/^[A-Za-z0-9_-]+$/);

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });
});

describe("3. signReceipt with tampered field fails verifySignature", () => {
  test("modifying a signed field after signing invalidates the signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeManifestFields());
    const signed = await signReceipt(unsigned, privKey);

    // Tamper with a signed field
    const tampered = { ...signed, agent_id: "evil-agent" } as SignedReceipt;

    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/invalid|fail/i);
  });
});

describe("4. chainReceipt sets correct prev_receipt_hash and sequence_number", () => {
  test("chained receipt has correct prev_receipt_hash and incremented sequence_number", async () => {
    const privKey = ed.utils.randomPrivateKey();

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    const actionFields = makeActionFields({ sequence_number: 1 });
    const chained = chainReceipt(createReceipt(actionFields), signedManifest);

    // sequence_number should be previous + 1
    expect(chained.sequence_number).toBe(signedManifest.sequence_number + 1);

    // prev_receipt_hash must be sha256:<64 hex chars>
    expect(chained.prev_receipt_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("chainReceipt computes hash from complete previous receipt including signature", async () => {
    const privKey = ed.utils.randomPrivateKey();

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    const actionFields = makeActionFields({ sequence_number: 1 });
    const chained = chainReceipt(createReceipt(actionFields), signedManifest);

    // Manually compute expected hash: SHA-256(JCS(complete signed manifest))
    const { createHash } = await import("crypto");
    const canonical = canonicalize(signedManifest as object);
    if (!canonical) throw new Error("canonicalize returned undefined");
    const expectedHash = "sha256:" + createHash("sha256").update(canonical).digest("hex");

    expect(chained.prev_receipt_hash).toBe(expectedHash);
  });
});

describe("5. verifyChain on valid 3-receipt chain passes", () => {
  test("3-receipt chain verifies successfully", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    // Receipt 0: workflow_manifest
    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    // Receipt 1: action_receipt chained from manifest
    const actionFields = makeActionFields({
      receipt_id: "01HXYZ000000000000000010",
      sequence_number: 1,
    });
    const chainedAction = chainReceipt(createReceipt(actionFields), signedManifest);
    const signedAction = await signReceipt(chainedAction, privKey);

    // Receipt 2: workflow_closed chained from action
    const closedFields = makeClosedFields({
      receipt_id: "01HXYZ000000000000000011",
      sequence_number: 2,
    });
    const chainedClosed = chainReceipt(createReceipt(closedFields), signedAction);
    const signedClosed = await signReceipt(chainedClosed, privKey);

    const result = await verifyChain([signedManifest, signedAction, signedClosed], pubKey);
    expect(result.valid).toBe(true);
    expect(result.gaps).toEqual([]);
  });
});

describe("6. verifyChain with sequence gap returns INCOMPLETE_CHAIN", () => {
  test("missing receipt in chain returns INCOMPLETE_CHAIN", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    const actionFields = makeActionFields({
      receipt_id: "01HXYZ000000000000000010",
      sequence_number: 1,
    });
    const chainedAction = chainReceipt(createReceipt(actionFields), signedManifest);
    const signedAction = await signReceipt(chainedAction, privKey);

    // Skip sequence_number 2, jump to 3
    const closedFields = makeClosedFields({
      receipt_id: "01HXYZ000000000000000011",
      sequence_number: 3, // gap: missing 2
    });
    const gappedClosed = chainReceipt(createReceipt(closedFields), signedAction);
    // Override sequence_number manually after chaining to create the gap
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- mutating readonly field to simulate gap for test
    (gappedClosed as any).sequence_number = 3;
    const signedClosed = await signReceipt(gappedClosed, privKey);

    const result = await verifyChain([signedManifest, signedAction, signedClosed], pubKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/INCOMPLETE_CHAIN/);
    expect(result.gaps.length).toBeGreaterThan(0);
    expect(result.errors[0].code).toBe("INCOMPLETE_CHAIN");
    expect(result.errors[0].index).toBe(2);
  });
});

describe("7. verifyChain with wrong prev_receipt_hash fails", () => {
  test("tampered prev_receipt_hash fails chain verification", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    const actionFields = makeActionFields({
      receipt_id: "01HXYZ000000000000000010",
      sequence_number: 1,
    });
    const chainedAction = chainReceipt(createReceipt(actionFields), signedManifest);
    // Tamper with prev_receipt_hash before signing
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- tamping readonly field to simulate hash mismatch for test
    (chainedAction as any).prev_receipt_hash =
      "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const signedAction = await signReceipt(chainedAction, privKey);

    const result = await verifyChain([signedManifest, signedAction], pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe("HASH_MISMATCH");
    expect(result.errors[0].index).toBe(1);
  });
});

describe("9. verifyChain with invalid signature returns L1_INVALID", () => {
  test("tampered signature.sig causes L1_INVALID error at correct index", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    // Tamper the first receipt's signature
    const tampered = {
      ...signedManifest,
      signature: {
        ...signedManifest.signature,
        sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    } as SignedReceipt;

    const result = await verifyChain([tampered], pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe("L1_INVALID");
    expect(result.errors[0].index).toBe(0);
  });
});

describe("8. Hash encoding", () => {
  test("all hash fields use sha256: prefix + 64 lowercase hex chars", async () => {
    const privKey = ed.utils.randomPrivateKey();

    const manifest = createReceipt(makeManifestFields());
    const signedManifest = await signReceipt(manifest, privKey);

    const actionFields = makeActionFields({
      receipt_id: "01HXYZ000000000000000010",
      sequence_number: 1,
    });
    const chainedAction = chainReceipt(createReceipt(actionFields), signedManifest);

    const hashRegex = /^sha256:[0-9a-f]{64}$/;

    // prev_receipt_hash on action receipt (chained from manifest)
    expect(chainedAction.prev_receipt_hash).toMatch(hashRegex);

    // policy_bundle_hash on manifest
    expect(manifest.policy_bundle_hash).toMatch(hashRegex);

    // params_canonical_hash on action
    const a = chainedAction as unknown as SignedActionReceipt;
    expect(a.params_canonical_hash).toMatch(hashRegex);
  });

  test("canonicalize and JSON.stringify produce different byte sequences for the same object", () => {
    // This test proves that canonicalize (JCS RFC 8785) behaves differently from JSON.stringify
    // for objects with non-lexicographic key order
    const obj = { z_key: "last", a_key: "first", m_key: "middle" };

    const jcsOutput = canonicalize(obj);
    const jsonOutput = JSON.stringify(obj);

    // JCS sorts keys lexicographically: a_key, m_key, z_key
    expect(jcsOutput).toBe('{"a_key":"first","m_key":"middle","z_key":"last"}');
    // JSON.stringify preserves insertion order: z_key, a_key, m_key
    expect(jsonOutput).toBe('{"z_key":"last","a_key":"first","m_key":"middle"}');

    // They MUST differ
    expect(jcsOutput).not.toBe(jsonOutput);
  });
});
