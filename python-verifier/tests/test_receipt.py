"""RC-: receipt model tests."""
from nonsudo_verify.models import (
    receipt_record_type,
    receipt_key_id,
    receipt_sequence_number,
    receipt_primary_id,
    is_valid_key_id,
    RECORD_TYPES,
    DECISIONS,
)


def test_rc01_record_type():
    assert receipt_record_type({"record_type": "workflow_manifest"}) == "workflow_manifest"
    assert receipt_record_type({"record_type": "action_receipt"}) == "action_receipt"
    assert receipt_record_type({}) is None


def test_rc02_key_id():
    assert receipt_key_id({"signature": {"key_id": "ns-test-01"}}) == "ns-test-01"
    assert receipt_key_id({"signature": {}}) is None
    assert receipt_key_id({}) is None


def test_rc03_sequence_number():
    assert receipt_sequence_number({"sequence_number": 5}) == 5
    assert receipt_sequence_number({}) == 0


def test_rc04_primary_id():
    assert receipt_primary_id({"receipt_id": "r1"}) == "r1"
    assert receipt_primary_id({"post_receipt_id": "p1"}) == "p1"
    assert receipt_primary_id({}) is None


def test_rc05_valid_key_id():
    assert is_valid_key_id("ns-test-01") is True
    assert is_valid_key_id("a") is True
    assert is_valid_key_id("") is False
    assert is_valid_key_id("x" * 65) is False
    assert is_valid_key_id("key/../etc") is False


def test_rc06_record_types_include_manifest():
    assert "workflow_manifest" in RECORD_TYPES
    assert "action_receipt" in RECORD_TYPES


def test_rc07_decisions():
    assert "ALLOW" in DECISIONS
    assert "BLOCK" in DECISIONS
