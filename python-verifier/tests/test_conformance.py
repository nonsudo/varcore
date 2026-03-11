"""CF-: conformance vector tests."""
import json
from pathlib import Path
import pytest
from nonsudo_verify.chain import load_ndjson
from nonsudo_verify.verifier import verify_chain
from nonsudo_verify.key_resolver import key_from_hex

FIXTURES = Path(__file__).parent / "fixtures" / "conformance"
TEST_KEY_HEX = "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06"


def _expected():
    p = FIXTURES / "expected.json"
    return json.loads(p.read_text()) if p.exists() else {}


@pytest.mark.parametrize("filename", sorted(FIXTURES.glob("TV_*_pass.ndjson"), key=lambda p: p.name))
def test_conformance_vector(filename):
    """Each conformance vector must yield expected L1/L2 outcome."""
    expected_map = _expected()
    # TV_01_pass.ndjson -> TV-01
    vector_id = filename.stem.replace("_pass", "").replace("_", "-")
    expected = expected_map.get(vector_id, {"expected_l1": "PASS", "expected_l2": "PASS"})
    receipts = load_ndjson(filename)
    pub = key_from_hex(TEST_KEY_HEX)
    r = verify_chain(receipts, str(filename), public_key=pub)
    assert r.l1_status == expected["expected_l1"], f"{vector_id}: expected L1 {expected['expected_l1']}, got {r.l1_status}"
    assert r.l2_status == expected["expected_l2"], f"{vector_id}: expected L2 {expected['expected_l2']}, got {r.l2_status}"
