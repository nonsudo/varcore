"""
Resolve Ed25519 public key (32 bytes) from flags, config, or key-cache.
Priority: --key-hex, --key (PEM file), --key-from-config (nonsudo.yaml), key-cache JWK.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def key_from_hex(hex_str: str) -> bytes | None:
    """Decode hex string to 32-byte public key. Strips optional 'hex:' prefix."""
    s = hex_str.strip()
    if s.startswith("hex:"):
        s = s[4:].strip()
    if len(s) != 64 or not all(c in "0123456789abcdefABCDEF" for c in s):
        return None
    return bytes.fromhex(s)


def key_from_pem_file(path: str | Path) -> bytes | None:
    """Load PEM file and return raw 32-byte public key."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = path.read_bytes()
        pub = serialization.load_pem_public_key(data)
        if not isinstance(pub, Ed25519PublicKey):
            return None
        return pub.public_bytes_raw()
    except Exception:
        return None


def key_from_jwk_file(path: str | Path) -> bytes | None:
    """Load JWK file (OKP Ed25519) and return 32-byte public key from 'x' (base64url)."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        jwk = json.loads(path.read_text(encoding="utf-8"))
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return None
        x = jwk.get("x")
        if not x:
            return None
        return base64.urlsafe_b64decode(x + "==")
    except Exception:
        return None


def key_from_config(yaml_path: str | Path) -> bytes | None:
    """Read nonsudo.yaml and return public_key (hex:...) as 32 bytes. No PyYAML dependency."""
    path = Path(yaml_path)
    if not path.exists():
        return None
    import re
    text = path.read_text(encoding="utf-8")
    m = re.search(r'public_key\s*:\s*["\']?(hex:[a-fA-F0-9]{64})["\']?', text)
    if not m:
        return None
    return key_from_hex(m.group(1))


def resolve_public_key(
    key_hex: str | None = None,
    key_file: str | Path | None = None,
    key_from_config_path: str | Path | None = None,
    key_id: str | None = None,
    key_cache_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
) -> bytes | None:
    """
    Resolve 32-byte public key. First non-None source wins.
    key_hex: --key-hex value (or hex from config)
    key_file: path to PEM file
    key_from_config_path: path to nonsudo.yaml for public_key field
    key_id: receipt.signature.key_id for cache lookup
    key_cache_dir: ~/.nonsudo/key-cache
    keys_dir: ~/.nonsudo/keys
    """
    if key_hex:
        k = key_from_hex(key_hex)
        if k is not None:
            return k
    if key_file:
        k = key_from_pem_file(key_file)
        if k is not None:
            return k
    if key_from_config_path:
        k = key_from_config(key_from_config_path)
        if k is not None:
            return k
    if key_id and key_cache_dir:
        p = Path(key_cache_dir) / f"{key_id}.jwk"
        k = key_from_jwk_file(p)
        if k is not None:
            return k
    if key_id and keys_dir:
        p = Path(keys_dir) / f"{key_id}.jwk"
        k = key_from_jwk_file(p)
        if k is not None:
            return k
    return None
