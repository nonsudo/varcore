"""CH-: chain load and sort tests."""
import json
import tempfile
from pathlib import Path
import pytest
from nonsudo_verify.chain import load_ndjson, load_tsa_sidecar, sort_receipts_by_sequence


def test_ch01_load_ndjson():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f:
        f.write('{"a":1}\n{"b":2}\n')
        path = f.name
    try:
        out = load_ndjson(path)
        assert len(out) == 2
        assert out[0]["a"] == 1
        assert out[1]["b"] == 2
    finally:
        Path(path).unlink()


def test_ch02_load_skips_empty_lines():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f:
        f.write('{"a":1}\n\n{"b":2}\n')
        path = f.name
    try:
        out = load_ndjson(path)
        assert len(out) == 2
    finally:
        Path(path).unlink()


def test_ch03_sort_by_sequence():
    receipts = [
        {"sequence_number": 2, "receipt_id": "c"},
        {"sequence_number": 0, "receipt_id": "a"},
        {"sequence_number": 1, "receipt_id": "b"},
    ]
    sorted_r = sort_receipts_by_sequence(receipts)
    assert [r["sequence_number"] for r in sorted_r] == [0, 1, 2]


def test_ch04_tsa_sidecar_missing_returns_empty():
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as f:
        path = f.name
    try:
        out = load_tsa_sidecar(path)
        assert out == []
    finally:
        Path(path).unlink()


def test_ch05_tsa_sidecar_parses_ndjson():
    ndjson_path = tempfile.mktemp(suffix=".ndjson")
    tsa_path = ndjson_path + ".tsa"
    Path(ndjson_path).touch()
    try:
        with open(tsa_path, "w") as f:
            f.write('{"receipt_id":"r1","rfc3161_token":"YQ==","tsa_id":"digicert","timestamped_at":"2026-01-01T00:00:00Z"}\n')
        out = load_tsa_sidecar(ndjson_path)
        assert len(out) == 1
        assert out[0]["tsa_id"] == "digicert"
    finally:
        Path(ndjson_path).unlink(missing_ok=True)
        Path(tsa_path).unlink(missing_ok=True)
