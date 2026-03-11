"""TS-: timestamp (L3) tests."""
import base64
import pytest
from nonsudo_verify.timestamp import receipt_canonical_hash, verify_tsa_record, SHA256_OID


def test_ts01_receipt_canonical_hash_deterministic():
    rec = {"receipt_id": "r1", "record_type": "workflow_manifest", "signature": {"sig": "x"}}
    h1 = receipt_canonical_hash(rec)
    h2 = receipt_canonical_hash(rec)
    assert h1 == h2
    assert len(h1) == 32


def test_ts02_tsa_record_wrong_tsa_id_fails():
    rec = {"receipt_id": "r1", "issued_at": "2026-01-01T00:00:00Z"}
    tsa_rec = {"receipt_id": "r1", "rfc3161_token": "YQ==", "tsa_id": "evil", "timestamped_at": "2026-01-01T00:00:00Z"}
    status, reason = verify_tsa_record(rec, tsa_rec)
    assert status == "FAIL"
    assert "allowlist" in (reason or "").lower() or "tsa" in (reason or "").lower()


def test_ts03_tsa_record_invalid_token_fails():
    rec = {"receipt_id": "r1", "issued_at": "2026-01-01T00:00:00Z"}
    tsa_rec = {"receipt_id": "r1", "rfc3161_token": "not-valid-base64!!!", "tsa_id": "digicert", "timestamped_at": "2026-01-01T00:00:00Z"}
    status, reason = verify_tsa_record(rec, tsa_rec)
    assert status == "FAIL"


def test_ts04_sha256_oid_constant():
    assert SHA256_OID == (2, 16, 840, 1, 101, 3, 4, 2, 1)
