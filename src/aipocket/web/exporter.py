"""Build plaintext export payloads (json/csv) as downloadable streams.

Datasets:
* ``selected``  — the exact ``{apikey, apiurl}`` rows the user checked;
* ``run``       — every key in a run's valid (or suspicious) file;
* ``high-value``— the full cross-run high-value log.

Exports always contain the FULL PLAINTEXT apikey (the point of exporting is to
use the key). The backend does not persist these files — the stream is built in
memory and handed straight to the browser download.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from ..high_value_writer import load_all
from .errors import ApiError
from .results_reader import load_run_records_plain
from .schemas import ExportRequest

# Column order for CSV exports — a stable superset covering all dataset shapes.
_CSV_FIELDS = [
    "apikey", "apiurl", "host", "provider", "status_code", "valid",
    "tier", "balance", "gateway", "model_available", "error", "suspicious_reason",
]


def _flatten(rec: dict[str, Any]) -> dict[str, Any]:
    """Flatten a ValidationResult-shaped dict into a single-level row."""
    cred = rec.get("credential") or {}
    prov = rec.get("provider_info") or {}
    return {
        "apikey": cred.get("apikey", rec.get("apikey", "")),
        "apiurl": cred.get("apiurl", rec.get("apiurl", "")),
        "host": cred.get("host", rec.get("host", "")),
        "provider": prov.get("provider", rec.get("provider", "")),
        "status_code": rec.get("status_code", ""),
        "valid": rec.get("valid", ""),
        "tier": rec.get("tier", ""),
        "balance": rec.get("balance", ""),
        "gateway": rec.get("gateway", ""),
        "model_available": rec.get("model_available", ""),
        "error": rec.get("error", ""),
        "suspicious_reason": rec.get("suspicious_reason", ""),
    }


def _collect(req: ExportRequest) -> list[dict[str, Any]]:
    if req.dataset == "selected":
        # Preferred path: read the plaintext keys server-side by index, so they
        # never round-trip through the browser.
        if req.run_id and req.indices:
            recs = load_run_records_plain(req.run_id, req.kind)
            return [_flatten(recs[i]) for i in req.indices if 0 <= i < len(recs)]
        # Legacy path: explicit plaintext key rows supplied by the client.
        if req.keys:
            return [{"apikey": k.apikey, "apiurl": k.apiurl} for k in req.keys]
        raise ApiError(
            "selected export requires 'run_id'+'indices' or 'keys'", code="bad_request"
        )

    if req.dataset == "run":
        if not req.run_id:
            raise ApiError("run export requires 'run_id'", code="bad_request")
        return [_flatten(r) for r in load_run_records_plain(req.run_id, req.kind)]

    if req.dataset == "high-value":
        return [_flatten(r) for r in load_all()]

    raise ApiError(f"unknown dataset: {req.dataset}", code="bad_request")


def build_export(req: ExportRequest) -> tuple[bytes, str, str]:
    """Return ``(content_bytes, media_type, filename)`` for the request."""
    rows = _collect(req)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"aipocket_{req.dataset}_{ts}"

    if req.format == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2).encode("utf-8")
        return content, "application/json", f"{stem}.json"

    # CSV
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        # selected rows only have apikey/apiurl — DictWriter fills the rest blank.
        writer.writerow(row)
    return buf.getvalue().encode("utf-8"), "text/csv", f"{stem}.csv"
