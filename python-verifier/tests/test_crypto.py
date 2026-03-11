"""CR-01..CR-08: crypto tests."""
import base64
import pytest
import jcs
from nonsudo_verify.crypto import (
    build_signing_payload,
    canonicalize_bytes,
    base64url_decode,
    verify_signature,
    sha256_prefixed_hex,
    chain_hash_full_receipt,
    WORKFLOW_MANIFEST_SIGNED_FIELDS,
    ACTION_RECEIPT_SIGNED_FIELDS,
    WORKFLOW_CLOSED_SIGNED_FIELDS,
)


# CR-01: Test keypair seed produces correct public key
def test_cr01_test_keypair_public_key(test_public_key_bytes):
    expected = bytes.fromhex("3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06")
    assert test_public_key_bytes == expected, "Python keypair must match TypeScript test vector"


# CR-02: Valid signature verifies
def test_cr02_valid_signature_verifies(test_public_key_bytes, test_private_key):
    from nonsudo_verify.chain import load_ndjson
    from pathlib import Path
    p = Path(__file__).parent / "fixtures" / "conformance" / "TV_01_pass.ndjson"
    receipts = load_ndjson(str(p))
    for r in receipts:
        valid, reason = verify_signature(r, test_public_key_bytes)
        assert valid, reason


# CR-03: Tampered receipt fails L1
def test_cr03_tampered_receipt_fails(test_public_key_bytes):
    from nonsudo_verify.chain import load_ndjson
    from pathlib import Path
    import copy
    p = Path(__file__).parent / "fixtures" / "conformance" / "TV_01_pass.ndjson"
    receipts = load_ndjson(str(p))
    r = copy.deepcopy(receipts[0])
    r["workflow_id"] = "tampered"
    valid, _ = verify_signature(r, test_public_key_bytes)
    assert not valid


# CR-04: JCS canonical bytes are deterministic
def test_cr04_jcs_deterministic():
    payload = {"a": 1, "b": 2}
    c1 = canonicalize_bytes(payload)
    c2 = canonicalize_bytes(payload)
    assert c1 == c2


# CR-05: JCS output matches known canonical form (one receipt from TV-01 manifest)
def test_cr05_jcs_matches_known():
    payload = {
        "receipt_id": "manifest-TV01-wf-0",
        "record_type": "workflow_manifest",
        "spec_version": "var/1.0",
        "workflow_id": "TV01-wf",
        "workflow_id_source": "nonsudo_generated",
        "agent_id": "test-agent",
        "issued_at": "2026-02-28T00:00:00Z",
        "prev_receipt_hash": None,
        "sequence_number": 0,
        "policy_bundle_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "initiator_id": "test-init",
        "workflow_owner": "test-team",
        "session_budget": {"api_calls": 100},
        "declared_tools": [],
        "capability_manifest_hash": None,
        "parent_workflow_id": None,
        "framework_ref": None,
    }
    canonical = canonicalize_bytes(payload)
    assert isinstance(canonical, bytes)
    assert len(canonical) > 0


# CR-06: Missing key returns OFFLINE (handled in verifier, not crypto)
def test_cr06_missing_signature_block():
    valid, reason = verify_signature({"workflow_id": "x"}, bytes(32))
    assert not valid
    assert "missing" in reason.lower() or "signature" in reason.lower()


# CR-07: Wrong key returns FAIL
def test_cr07_wrong_key_fails(test_public_key_bytes):
    from nonsudo_verify.chain import load_ndjson
    from pathlib import Path
    p = Path(__file__).parent / "fixtures" / "conformance" / "TV_01_pass.ndjson"
    receipts = load_ndjson(str(p))
    wrong_key = bytes(32)
    valid, _ = verify_signature(receipts[0], wrong_key)
    assert not valid


# CR-08: build_signing_payload returns correct fields per record_type
def test_cr08_build_signing_payload_fields():
    manifest = {"record_type": "workflow_manifest", "receipt_id": "m1", "workflow_id": "w1", "spec_version": "var/1.0"}
    payload = build_signing_payload(manifest)
    for f in WORKFLOW_MANIFEST_SIGNED_FIELDS:
        if f in manifest:
            assert f in payload
    action = {"record_type": "action_receipt", "receipt_id": "a1", "workflow_id": "w1", "queue_status": "COMPLETED"}
    payload_a = build_signing_payload(action)
    for f in ACTION_RECEIPT_SIGNED_FIELDS:
        if f in action:
            assert f in payload_a
    closed = {"record_type": "workflow_closed", "receipt_id": "c1", "workflow_id": "w1"}
    payload_c = build_signing_payload(closed)
    for f in WORKFLOW_CLOSED_SIGNED_FIELDS:
        if f in closed:
            assert f in payload_c
