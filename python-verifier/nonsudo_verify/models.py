"""
Receipt and verification result models.
Derived from packages/receipts/src/types.ts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Record types (Section 3) — must match TypeScript RecordType
RECORD_TYPES = frozenset({
    "workflow_manifest",
    "action_receipt",
    "workflow_closed",
    "post_receipt",
    "recovery_event",
    "budget_warning",
    "reservation_expired",
    "approval_receipt",
})

# Decisions — match TypeScript Decision
DECISIONS = frozenset({"ALLOW", "BLOCK", "FAIL_OPEN", "FAIL_CLOSED", "STEP_UP"})

# Queue status
QUEUE_STATUSES = frozenset({"COMPLETED", "DEAD_LETTER"})

# L3/L4 status
TIER_STATUS = frozenset({"PASS", "FAIL", "SKIPPED", "OFFLINE", "PENDING", "WARN", "N/A"})


def is_valid_key_id(key_id: str) -> bool:
    """Safe for filesystem and URL: [a-zA-Z0-9_-]{1,64}."""
    if not key_id or len(key_id) > 64:
        return False
    return all(c.isalnum() or c in "-_" for c in key_id)


@dataclass
class TsaRecord:
    """One record in the .tsa sidecar file (NDJSON line)."""
    receipt_id: str
    rfc3161_token: str  # base64 DER TimeStampResp
    tsa_id: str
    timestamped_at: str  # RFC3339


@dataclass
class VerifyResult:
    """Result of verifying one chain."""
    chain_path: str
    receipt_count: int
    l1_status: str  # PASS | FAIL | OFFLINE
    l1_detail: str | None
    l2_status: str
    l2_detail: str | None
    l3_status: str  # PASS | FAIL | SKIPPED | PENDING
    l3_detail: str | None
    l4_status: str  # PASS | FAIL | WARN | N/A
    l4_detail: str | None
    overall: str  # PASS | FAIL
    warnings: list[str] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return self.overall == "PASS"


def receipt_record_type(receipt: dict[str, Any]) -> str | None:
    """Return record_type from receipt; None if missing."""
    return receipt.get("record_type")


def receipt_key_id(receipt: dict[str, Any]) -> str | None:
    """Return signature.key_id from receipt."""
    sig = receipt.get("signature")
    if not isinstance(sig, dict):
        return None
    return sig.get("key_id")


def receipt_sequence_number(receipt: dict[str, Any]) -> int:
    """Return sequence_number; 0 if missing."""
    val = receipt.get("sequence_number", 0)
    return int(val) if val is not None else 0


def receipt_primary_id(receipt: dict[str, Any]) -> str | None:
    """Primary ID for L3: receipt_id, or post_receipt_id, recovery_event_id, etc."""
    for key in (
        "receipt_id",
        "post_receipt_id",
        "recovery_event_id",
        "budget_warning_id",
        "reservation_expired_id",
    ):
        val = receipt.get(key)
        if val is not None and isinstance(val, str):
            return str(val)
    return None
