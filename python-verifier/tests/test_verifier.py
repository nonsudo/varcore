"""VR-: verifier integration tests."""
from pathlib import Path
import pytest
from nonsudo_verify.chain import load_ndjson
from nonsudo_verify.key_resolver import key_from_hex
from nonsudo_verify.verifier import verify_chain


FIXTURES = Path(__file__).parent / "fixtures" / "conformance"
TEST_KEY_HEX = "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06"


def test_vr01_tv01_pass():
    receipts = load_ndjson(FIXTURES / "TV_01_pass.ndjson")
    pub = key_from_hex(TEST_KEY_HEX)
    r = verify_chain(receipts, "TV_01_pass.ndjson", public_key=pub)
    assert r.l1_status == "PASS"
    assert r.l2_status == "PASS"
    assert r.overall == "PASS"


def test_vr02_tv02_pass():
    receipts = load_ndjson(FIXTURES / "TV_02_pass.ndjson")
    pub = key_from_hex(TEST_KEY_HEX)
    r = verify_chain(receipts, "TV_02_pass.ndjson", public_key=pub)
    assert r.overall == "PASS"


def test_vr03_empty_chain():
    r = verify_chain([], "empty.ndjson")
    assert r.receipt_count == 0
    assert r.overall == "PASS"


def test_vr04_tampered_prev_hash_fails():
    receipts = load_ndjson(FIXTURES / "TV_01_pass.ndjson")
    pub = key_from_hex(TEST_KEY_HEX)
    receipts[1] = {**receipts[1], "prev_receipt_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
    r = verify_chain(receipts, "tampered.ndjson", public_key=pub)
    assert r.l2_status == "FAIL"


def test_vr05_resolve_key_by_key_id():
    receipts = load_ndjson(FIXTURES / "TV_01_pass.ndjson")
    r = verify_chain(receipts, "TV_01_pass.ndjson", key_id="ns-test-01")
    assert r.l1_status in ("PASS", "OFFLINE")


def test_vr06_l4_na_without_money_action():
    receipts = load_ndjson(FIXTURES / "TV_01_pass.ndjson")
    pub = key_from_hex(TEST_KEY_HEX)
    r = verify_chain(receipts, "TV_01.ndjson", public_key=pub)
    assert r.l4_status == "N/A"
