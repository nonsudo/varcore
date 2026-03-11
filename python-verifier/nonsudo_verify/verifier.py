"""
L1–L4 verification orchestration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nonsudo_verify import models
from nonsudo_verify.chain import load_ndjson, load_tsa_sidecar, sort_receipts_by_sequence
from nonsudo_verify.crypto import (
    chain_hash_full_receipt,
    verify_signature,
)
from nonsudo_verify.timestamp import (
    DEFAULT_ACCEPTING_TSA_IDS,
    receipt_canonical_hash,
    verify_tsa_record,
)
from nonsudo_verify.key_resolver import resolve_public_key


def _l1(
    receipts: list[dict[str, Any]],
    public_key: bytes | None,
    key_id: str | None,
    key_cache_dir: Path | None,
    keys_dir: Path | None,
) -> tuple[str, str | None]:
    """L1: Ed25519 signature verification. Returns (status, detail)."""
    if not receipts:
        return "PASS", None
    if public_key is None and key_id:
        pub = resolve_public_key(
            key_id=key_id,
            key_cache_dir=str(key_cache_dir) if key_cache_dir else None,
            keys_dir=str(keys_dir) if keys_dir else None,
        )
        if pub is None:
            return "OFFLINE", "public key not resolved"
        public_key = pub
    if public_key is None:
        return "OFFLINE", "no public key"
    passed = 0
    for r in receipts:
        valid, reason = verify_signature(r, public_key)
        if not valid:
            return "FAIL", reason
        passed += 1
    return "PASS", f"{passed}/{len(receipts)} signatures valid"


def _l2(receipts: list[dict[str, Any]]) -> tuple[str, str | None]:
    """L2: Hash chain integrity. Sort by sequence_number; prev_receipt_hash = sha256(JCS(prev full receipt))."""
    sorted_r = sort_receipts_by_sequence(receipts)
    if not sorted_r:
        return "PASS", None
    # First receipt must be workflow_manifest
    if sorted_r[0].get("record_type") != "workflow_manifest":
        return "FAIL", "first receipt must be workflow_manifest"
    # C3: spec_version must be var/1.0
    for i, r in enumerate(sorted_r):
        if r.get("spec_version") != "var/1.0":
            return "FAIL", f"receipt[{i}] spec_version must be 'var/1.0'"
    # First receipt: prev_receipt_hash must be null
    if sorted_r[0].get("prev_receipt_hash") is not None:
        return "FAIL", "receipt[0] prev_receipt_hash must be null"
    if sorted_r[0].get("sequence_number") != 0:
        return "FAIL", "receipt[0] sequence_number must be 0"
    if len(sorted_r) <= 1:
        return "PASS", None
    workflow_id = sorted_r[0].get("workflow_id")
    for i in range(1, len(sorted_r)):
        prev = sorted_r[i - 1]
        curr = sorted_r[i]
        if curr.get("workflow_id") != workflow_id:
            return "FAIL", f"workflow_id mismatch at receipt[{i}]"
        expected_seq = prev.get("sequence_number", 0) + 1
        if curr.get("sequence_number") != expected_seq:
            return "FAIL", f"sequence gap at receipt[{i}]"
        expected_hash = chain_hash_full_receipt(prev)
        if curr.get("prev_receipt_hash") != expected_hash:
            return "FAIL", f"prev_receipt_hash mismatch at receipt[{i}]"
    return "PASS", None


def _l3(
    receipts: list[dict[str, Any]],
    tsa_records: list[dict[str, Any]],
    accepting_tsa_ids: list[str] | None = None,
) -> tuple[str, str | None]:
    """L3: Timestamp authority. SKIPPED if no sidecar; PASS/FAIL per receipt with TSA record."""
    if not receipts:
        return "SKIPPED", None
    accepting = accepting_tsa_ids or DEFAULT_ACCEPTING_TSA_IDS
    record_by_id = {r["receipt_id"]: r for r in tsa_records if "receipt_id" in r}
    passed = 0
    any_checked = False
    for rec in receipts:
        primary_id = models.receipt_primary_id(rec)
        if not primary_id:
            continue
        tsa_rec = record_by_id.get(primary_id)
        if not tsa_rec:
            continue
        any_checked = True
        status, reason = verify_tsa_record(rec, tsa_rec, accepting)
        if status == "FAIL":
            return "FAIL", reason
        passed += 1
    if not any_checked:
        return "SKIPPED", None
    return "PASS", f"{passed}/{len(receipts)} timestamps valid"


def _l4(receipts: list[dict[str, Any]]) -> tuple[str, str | None, list[str]]:
    """
    L4: Outcome binding. RI-1: every ALLOW'd money action has a terminal post_receipt.
    Returns (status, detail, warnings).
    """
    warnings: list[str] = []
    money_allow_ids: list[str] = []
    resolved_pre_ids: set[str] = set()
    for r in receipts:
        if r.get("record_type") == "action_receipt" and r.get("money_action") is True and r.get("decision") == "ALLOW":
            rid = r.get("receipt_id")
            if rid:
                money_allow_ids.append(rid)
        if r.get("record_type") == "post_receipt":
            pre = r.get("pre_receipt_id")
            if pre:
                resolved_pre_ids.add(pre)
        if r.get("record_type") == "budget_warning":
            warnings.append("budget_warning present")
    if not money_allow_ids:
        return "N/A", None, warnings
    for rid in money_allow_ids:
        if rid not in resolved_pre_ids:
            return "FAIL", f"money action receipt_id={rid} has no terminal post_receipt", warnings
    return "PASS", None, warnings


def verify_chain(
    receipts: list[dict[str, Any]],
    chain_path: str,
    public_key: bytes | None = None,
    key_id: str | None = None,
    key_cache_dir: Path | None = None,
    keys_dir: Path | None = None,
    tsa_records: list[dict[str, Any]] | None = None,
    accepting_tsa_ids: list[str] | None = None,
) -> models.VerifyResult:
    """Run L1–L4 on a sorted receipt list. Resolves key from key_id if public_key not provided."""
    home = Path(os.environ.get("HOME", os.path.expanduser("~")))
    key_cache_dir = key_cache_dir or home / ".nonsudo" / "key-cache"
    keys_dir = keys_dir or home / ".nonsudo" / "keys"
    sorted_r = sort_receipts_by_sequence(receipts)
    if not sorted_r:
        return models.VerifyResult(
            chain_path=chain_path,
            receipt_count=0,
            l1_status="PASS",
            l1_detail=None,
            l2_status="PASS",
            l2_detail=None,
            l3_status="SKIPPED",
            l3_detail=None,
            l4_status="N/A",
            l4_detail=None,
            overall="PASS",
        )
    kid = key_id or (sorted_r[0].get("signature") or {}).get("key_id")
    l1_status, l1_detail = _l1(sorted_r, public_key, kid, key_cache_dir, keys_dir)
    l2_status, l2_detail = _l2(sorted_r)
    tsa = tsa_records or []
    l3_status, l3_detail = _l3(sorted_r, tsa, accepting_tsa_ids)
    l4_status, l4_detail, warn_list = _l4(sorted_r)
    overall = "FAIL" if l1_status == "FAIL" or l2_status == "FAIL" or l3_status == "FAIL" or l4_status == "FAIL" else "PASS"
    return models.VerifyResult(
        chain_path=chain_path,
        receipt_count=len(sorted_r),
        l1_status=l1_status,
        l1_detail=l1_detail,
        l2_status=l2_status,
        l2_detail=l2_detail,
        l3_status=l3_status,
        l3_detail=l3_detail,
        l4_status=l4_status,
        l4_detail=l4_detail,
        overall=overall,
        warnings=warn_list,
    )
