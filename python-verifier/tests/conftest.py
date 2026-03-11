"""Pytest fixtures for nonsudo-verify tests."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Test keypair: seed from scripts/generate-test-vectors.ts ("dead".repeat(16))
# Public key must match: 3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06
TEST_PRIVATE_KEY_SEED = bytes.fromhex("dead" * 16)
TEST_PUBLIC_KEY_HEX = "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06"


@pytest.fixture(scope="session")
def test_private_key():
    """Ed25519 private key from deterministic seed (matches TypeScript test vectors)."""
    return Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY_SEED)


@pytest.fixture(scope="session")
def test_public_key_bytes(test_private_key):
    """Raw 32-byte public key for verification."""
    return test_private_key.public_key().public_bytes_raw()
