"""
L1: Ed25519 signature verification.
Payload = build_signing_payload(receipt) — record_type-specific field subset, then JCS (RFC 8785).
Signature: base64url (no padding). Public key: 32 raw bytes.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nonsudo_verify.models import is_valid_key_id

# ── Signed field sets (must match packages/receipts/src/index.ts exactly) ───

BASE_SIGNED_FIELDS = [
    "receipt_id",
    "record_type",
    "spec_version",
    "workflow_id",
    "workflow_id_source",
    "agent_id",
    "issued_at",
    "prev_receipt_hash",
    "sequence_number",
    "policy_bundle_hash",
]

ACTION_RECEIPT_SIGNED_FIELDS = BASE_SIGNED_FIELDS + [
    "tool_name",
    "params_canonical_hash",
    "decision",
    "decision_reason",
    "decision_order",
    "queue_status",
    "queue_timeout_ms",
    "blast_radius",
    "reversible",
    "state_version_before",
    "state_version_after",
    "response_hash",
    "upstream_call_initiated",
    "money_action",
    "amount_minor_units",
    "billable",
    "billable_reason",
]

DEAD_LETTER_EXTRA_FIELDS = [
    "failure_reason",
    "fallback_policy",
]

WORKFLOW_MANIFEST_SIGNED_FIELDS = BASE_SIGNED_FIELDS + [
    "initiator_id",
    "workflow_owner",
    "session_budget",
    "declared_tools",
    "capability_manifest_hash",
    "parent_workflow_id",
    "framework_ref",
    "declared_tools_fetch_failed",
    "mode",
    "taxonomy_status",
    "money_action_overrides",
]

POST_RECEIPT_SIGNED_FIELDS = [
    "post_receipt_id",
    "record_type",
    "spec_version",
    "pre_receipt_id",
    "workflow_id",
    "agent_id",
    "sequence_number",
    "prev_receipt_hash",
    "policy_bundle_hash",
    "tool_name",
    "terminal_outcome",
    "upstream_response_digest",
    "projection_id",
    "projection_hash",
    "idempotency_key",
    "tool_call_correlation_id",
    "execution_start_ms",
    "execution_end_ms",
    "degraded_reason",
    "billable",
    "billable_reason",
    "issued_at",
    "account_context",
]

RECOVERY_EVENT_SIGNED_FIELDS = [
    "recovery_event_id",
    "record_type",
    "spec_version",
    "workflow_id",
    "agent_id",
    "sequence_number",
    "prev_receipt_hash",
    "policy_bundle_hash",
    "recovered_open_pres_count",
    "index_status",
    "recovery_method",
    "scan_window_minutes",
    "scan_receipts_examined",
    "issued_at",
]

BUDGET_WARNING_SIGNED_FIELDS = [
    "budget_warning_id",
    "record_type",
    "spec_version",
    "workflow_id",
    "agent_id",
    "sequence_number",
    "prev_receipt_hash",
    "policy_bundle_hash",
    "tool_name",
    "spent",
    "reserved",
    "cap",
    "threshold_pct",
    "issued_at",
]

RESERVATION_EXPIRED_SIGNED_FIELDS = [
    "reservation_expired_id",
    "record_type",
    "spec_version",
    "workflow_id",
    "agent_id",
    "sequence_number",
    "prev_receipt_hash",
    "policy_bundle_hash",
    "pre_receipt_id",
    "amount_released",
    "currency",
    "reason",
    "issued_at",
]

WORKFLOW_CLOSED_SIGNED_FIELDS = BASE_SIGNED_FIELDS + [
    "total_calls",
    "total_blocked",
    "total_spend",
    "session_duration_ms",
    "close_reason",
]


def build_signing_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """
    Build the object that was signed: only signed=yes fields for this record_type.
    Matches TypeScript buildSigningPayload() in packages/receipts/src/index.ts.
    """
    record_type = receipt.get("record_type")
    r = receipt

    if record_type == "workflow_manifest":
        fields = WORKFLOW_MANIFEST_SIGNED_FIELDS
    elif record_type == "action_receipt":
        fields = list(ACTION_RECEIPT_SIGNED_FIELDS)
        if r.get("queue_status") == "DEAD_LETTER":
            fields = fields + DEAD_LETTER_EXTRA_FIELDS
    elif record_type == "post_receipt":
        fields = POST_RECEIPT_SIGNED_FIELDS
    elif record_type == "recovery_event":
        fields = RECOVERY_EVENT_SIGNED_FIELDS
    elif record_type == "budget_warning":
        fields = BUDGET_WARNING_SIGNED_FIELDS
    elif record_type == "reservation_expired":
        fields = RESERVATION_EXPIRED_SIGNED_FIELDS
    else:
        # workflow_closed (and approval_receipt falls here in TS)
        fields = WORKFLOW_CLOSED_SIGNED_FIELDS

    payload: dict[str, Any] = {}
    for key in fields:
        if key in r:
            payload[key] = r[key]
    return payload


def canonicalize_bytes(payload: dict[str, Any]) -> bytes:
    """JCS (RFC 8785) canonicalize payload to UTF-8 bytes for signing/verification."""
    out = jcs.canonicalize(payload)
    if isinstance(out, str):
        return out.encode("utf-8")
    assert isinstance(out, bytes), "jcs.canonicalize should return str or bytes"
    return out


def base64url_decode(s: str) -> bytes:
    """Decode base64url (no padding)."""
    pad = 4 - len(s) % 4
    if pad != 4:
        s = s + "=" * pad
    return base64.urlsafe_b64decode(s)


def sha256_prefixed_hex(data: str) -> str:
    """SHA-256 hash of UTF-8 string, formatted as sha256:<hex>."""
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return "sha256:" + h


def verify_signature(
    receipt: dict[str, Any],
    public_key_bytes: bytes,
) -> tuple[bool, str]:
    """
    Verify Ed25519 signature on receipt.
    Returns (valid, reason).
    """
    sig_block = receipt.get("signature")
    if not isinstance(sig_block, dict):
        return False, "missing signature block"
    key_id = sig_block.get("key_id")
    if not key_id or not is_valid_key_id(key_id):
        return False, f"invalid key_id: {key_id!r}"
    sig_b64 = sig_block.get("sig")
    if not sig_b64 or not isinstance(sig_b64, str):
        return False, "missing or invalid signature.sig"

    # Reconstruct payload (receipt without signature)
    receipt_without_sig = {k: v for k, v in receipt.items() if k != "signature"}
    payload = build_signing_payload(receipt_without_sig)
    canonical_bytes = canonicalize_bytes(payload)

    try:
        sig_bytes = base64url_decode(sig_b64)
    except Exception as e:
        return False, f"signature decode error: {e}"

    if len(public_key_bytes) != 32:
        return False, "public key must be 32 bytes"

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(sig_bytes, canonical_bytes)
        return True, "signature valid"
    except InvalidSignature:
        return False, "signature invalid or failed verification"
    except Exception as e:
        return False, f"verification error: {e}"


def chain_hash_full_receipt(receipt: dict[str, Any]) -> str:
    """
    prev_receipt_hash = sha256(JCS(complete previous receipt)) — full receipt including signature.
    Matches TypeScript chainReceipt / verifyChain.
    """
    canonical = jcs.canonicalize(receipt)
    if isinstance(canonical, bytes):
        canonical = canonical.decode("utf-8")
    return sha256_prefixed_hex(canonical)
