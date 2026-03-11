"""
Load and sort receipt chains (NDJSON).
L2: prev_receipt_hash = sha256(JCS(complete previous receipt)) — full receipt including signature.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_ndjson(path: str | Path) -> list[dict]:
    """Load NDJSON file; one JSON object per line. Skip empty lines."""
    path = Path(path)
    receipts = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            receipts.append(json.loads(line))
    return receipts


def load_tsa_sidecar(ndjson_path: str | Path) -> list[dict]:
    """Load .tsa sidecar: same path as receipts file + '.tsa', NDJSON of TsaRecord per line."""
    path = Path(ndjson_path)
    tsa_path = path.with_suffix(path.suffix + ".tsa")
    if not tsa_path.exists():
        return []
    records = []
    with tsa_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def sort_receipts_by_sequence(receipts: list[dict]) -> list[dict]:
    """Sort by sequence_number (handles out-of-order NDJSON). Stable sort."""
    return sorted(receipts, key=lambda r: (r.get("sequence_number", 0), r.get("receipt_id", "")))
