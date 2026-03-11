"""Cross-verification: TypeScript-generated chains verify in Python."""
import shutil
import subprocess
from pathlib import Path
import pytest
from nonsudo_verify.chain import load_ndjson
from nonsudo_verify.verifier import verify_chain
from nonsudo_verify.key_resolver import key_from_hex

TEST_KEY_HEX = "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06"


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("nonsudo") is None, reason="nonsudo CLI not installed")
def test_typescript_refund_loop_chain():
    """TypeScript-generated refund-loop chain verifies in Python."""
    subprocess.run(["nonsudo", "demo", "stripe-refunds-loop"], check=True, capture_output=True)
    receipts_dir = Path("receipts")
    if not receipts_dir.exists():
        pytest.skip("receipts dir not created by demo")
    chains = list(receipts_dir.glob("demo-*"))
    if not chains:
        pytest.skip("no demo chain found")
    latest = sorted(chains, key=lambda p: p.stat().st_mtime)[-1]
    ndjson = list(latest.glob("*.ndjson"))
    if not ndjson:
        pytest.skip("no ndjson in chain dir")
    receipts = load_ndjson(ndjson[0])
    pub = key_from_hex(TEST_KEY_HEX)
    result = verify_chain(receipts, str(ndjson[0]), public_key=pub)
    assert result.l1_status == "PASS"
    assert result.l2_status == "PASS"
    assert result.overall == "PASS"


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("nonsudo") is None, reason="nonsudo CLI not installed")
def test_typescript_spend_cap_chain():
    """TypeScript-generated spend-cap chain verifies in Python."""
    subprocess.run(["nonsudo", "demo", "spend-cap"], check=True, capture_output=True)
    receipts_dir = Path("receipts")
    if not receipts_dir.exists():
        pytest.skip("receipts dir not created by demo")
    chains = list(receipts_dir.glob("demo-*"))
    if not chains:
        pytest.skip("no demo chain found")
    latest = sorted(chains, key=lambda p: p.stat().st_mtime)[-1]
    ndjson = list(latest.glob("*.ndjson"))
    if not ndjson:
        pytest.skip("no ndjson in chain dir")
    receipts = load_ndjson(ndjson[0])
    pub = key_from_hex(TEST_KEY_HEX)
    result = verify_chain(receipts, str(ndjson[0]), public_key=pub)
    assert result.l1_status == "PASS"
    assert result.l2_status == "PASS"
    assert result.overall == "PASS"
