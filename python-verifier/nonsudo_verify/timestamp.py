"""
L3: RFC 3161 timestamp verification.
messageImprint = SHA-256(JCS(complete signed receipt)).
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from typing import Any

import jcs
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc3161, rfc5652

SHA256_OID = (2, 16, 840, 1, 101, 3, 4, 2, 1)
DEFAULT_ACCEPTING_TSA_IDS = ["digicert", "sectigo", "globalsign"]


def _tst_info_from_resp(der_bytes: bytes) -> tuple[Any, Any] | None:
    """Parse TimeStampResp DER and return (TSTInfo, messageImprint). Returns None on parse error."""
    try:
        ts_resp, _ = decoder.decode(der_bytes, asn1Spec=rfc3161.TimeStampResp())
        if not ts_resp.getComponentByName("timeStampToken"):
            return None
        token = ts_resp.getComponentByName("timeStampToken")
        # ContentInfo: contentType, content (SignedData)
        content = token.getComponentByName("content")
        if content is None or hasattr(content, "isValue") and not content.isValue:
            return None
        # content is SignedData (implicit)
        signed_data, _ = decoder.decode(content, asn1Spec=rfc5652.SignedData())
        encap = signed_data.getComponentByName("encapContentInfo")
        e_content = encap.getComponentByName("eContent")
        if e_content is None:
            return None
        # eContent can be OctetString (TSTInfo DER)
        tst_der = bytes(e_content)
        tst_info, _ = decoder.decode(tst_der, asn1Spec=rfc3161.TSTInfo())
        return tst_info, tst_info.getComponentByName("messageImprint")
    except Exception:
        return None


def receipt_canonical_hash(receipt: dict[str, Any]) -> bytes:
    """SHA-256(JCS(complete signed receipt)) for L3 messageImprint."""
    canonical = jcs.canonicalize(receipt)
    if isinstance(canonical, bytes):
        canonical = canonical.decode("utf-8")
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def verify_tsa_record(
    receipt: dict[str, Any],
    tsa_record: dict[str, Any],
    accepting_tsa_ids: list[str] | None = None,
) -> tuple[str, str | None]:
    """
    Verify one TSA record against one receipt.
    Returns (status, reason). status in PASS | FAIL; reason set on FAIL.
    """
    accepting = accepting_tsa_ids or DEFAULT_ACCEPTING_TSA_IDS
    tsa_id = tsa_record.get("tsa_id") or ""
    if tsa_id not in accepting:
        return "FAIL", "tsa_not_in_allowlist"
    try:
        der_bytes = base64.b64decode(tsa_record["rfc3161_token"])
    except Exception:
        return "FAIL", "tsa_der_parse_error"
    parsed = _tst_info_from_resp(der_bytes)
    if not parsed:
        return "FAIL", "tsa_der_parse_error"
    tst_info, message_imprint = parsed
    # C1: SHA-256 OID
    hash_alg = message_imprint.getComponentByName("hashAlgorithm")
    oid = hash_alg.getComponentByName("algorithm")
    oid_tuple = tuple(oid)
    if oid_tuple != SHA256_OID:
        return "FAIL", "tsa_hash_algorithm_not_sha256"
    # C2: genTime >= issued_at
    gen_time = tst_info.getComponentByName("genTime")
    gen_time_str = str(gen_time)
    try:
        gen_dt = datetime.fromisoformat(gen_time_str.replace("Z", "+00:00"))
    except Exception:
        return "FAIL", "tsa_gentime_parse_error"
    issued_at = receipt.get("issued_at")
    if issued_at:
        try:
            issued_dt = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
            if gen_dt.timestamp() < issued_dt.timestamp():
                return "FAIL", "tsa_gentime_before_issued_at"
        except Exception:
            return "FAIL", "tsa_gentime_parse_error"
    # messageImprint
    expected_hash = receipt_canonical_hash(receipt)
    hashed_msg = bytes(message_imprint.getComponentByName("hashedMessage"))
    if hashed_msg != expected_hash:
        return "FAIL", "tsa_messageimprint_mismatch"
    return "PASS", None
