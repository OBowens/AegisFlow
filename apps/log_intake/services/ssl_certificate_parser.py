"""Parser for SSL/TLS certificate inventory exports (CSV, one certificate per row).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/ssl_certificate_50.csv, a hand-authored synthetic
sample (see that fixture set's own README) -- NOT a real certificate scan.
Column names and value ranges below reflect that fixture only.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

This format is a point-in-time inventory snapshot, not an event stream: each
row already carries a pre-computed `status` (VALID/WARNING/CRITICAL/EXPIRED/
NAME_MISMATCH) and `days_remaining`, so there is nothing to infer -- this
parser is close to a pure field mapping, which is why confidence_score is
uniformly the highest of any parser in this batch (0.99) for all five known
status values.

`timestamp` is deliberately left None for every row. `valid_from`/`valid_to`
describe the certificate's validity *window*, not when this inventory record
was generated or observed -- there is no field in this format that actually
answers "when did this event happen", so rather than repurpose one of those
dates as a stand-in event time, timestamp stays unset. account is always ""
for the same reason PRTG's is: certificate inventory has no applicable
username.

Severity treats EXPIRED and CRITICAL (PRTG-style "about to expire", observed
in the fixture at single-digit days_remaining) as equally severe, since both
mean the certificate cannot be trusted to keep working; NAME_MISMATCH is
scored high rather than critical because it is a configuration problem that
may not affect the certificate's cryptographic validity at all.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from io import StringIO


@dataclass
class ParsedSSLCertificateEvent:
    """Mirrors the non-relational fields of log_intake.models.ParsedAlert."""

    timestamp: datetime | None
    affected_system: str
    account: str
    source_ip: str | None
    destination_ip: str | None
    event_type: str
    severity_hint: str
    raw_message: str
    normalized_summary: str
    confidence_score: float
    source_tool: str = "ssl_certificate"


# status -> (event_type, severity_hint). Confidence is uniform (see module
# docstring) since status is already a computed, structured field.
_STATUS_META = {
    "valid": ("certificate_valid", "low"),
    "warning": ("certificate_expiring_soon", "medium"),
    "critical": ("certificate_expiring_critical", "critical"),
    "expired": ("certificate_expired", "critical"),
    "name_mismatch": ("certificate_name_mismatch", "high"),
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("_", text.lower()).strip("_") or "certificate"


def parse_ssl_certificate_log(
    raw_text: str, *, source_tool: str = "ssl_certificate"
) -> list[ParsedSSLCertificateEvent]:
    """Parse an SSL certificate inventory CSV export into one event per row."""

    reader = csv.DictReader(StringIO(raw_text))
    events: list[ParsedSSLCertificateEvent] = []

    for row in reader:
        if not any((value or "").strip() for value in row.values()):
            continue
        events.append(_to_event(row, source_tool))

    return events


def _to_event(row: dict, source_tool: str) -> ParsedSSLCertificateEvent:
    status = (row.get("status") or "").strip()
    status_key = status.lower()
    hostname = (row.get("hostname") or "").strip() or "Unknown system"
    common_name = (row.get("common_name") or "").strip()
    issuer = (row.get("issuer") or "").strip()
    valid_to = (row.get("valid_to") or "").strip()
    days_remaining = (row.get("days_remaining") or "").strip()

    if status_key in _STATUS_META:
        event_type, severity_hint = _STATUS_META[status_key]
        confidence = 0.99
    else:
        event_type = f"certificate_{_slugify(status)}" if status else "certificate_event"
        severity_hint = "unknown"
        confidence = 0.5

    summary_bits = [f"Certificate for {hostname} is {status or 'unknown'}"]
    if common_name and common_name != hostname:
        summary_bits.append(f"(common_name={common_name})")
    if issuer:
        summary_bits.append(f"issued by {issuer}")
    if valid_to:
        summary_bits.append(f"expires {valid_to}")
    if days_remaining:
        summary_bits.append(f"({days_remaining} days remaining)")
    summary = " ".join(summary_bits) + "."

    return ParsedSSLCertificateEvent(
        timestamp=None,
        affected_system=hostname,
        account="",
        source_ip=None,
        destination_ip=None,
        event_type=event_type,
        severity_hint=severity_hint,
        raw_message=", ".join(f"{key}={value}" for key, value in row.items()),
        normalized_summary=summary[:255],
        confidence_score=round(confidence, 2),
        source_tool=source_tool,
    )
