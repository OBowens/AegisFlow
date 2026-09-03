"""Best-effort content sniffing to guess an uploaded file's source type.

This mirrors the same structural signals the dedicated parsers themselves
key off of -- see each parser's ``_to_event``/``parse_*_log`` for the
authoritative version of these checks:

- Wazuh (JSON lines): top-level "rule" and "agent" objects
  (rule.id / rule.level, agent.name) -- wazuh_parser._to_event.
- Graylog (JSON lines): top-level "facility" and "message" strings, with
  no "rule"/"agent"/"EventID" present -- graylog_parser._to_event.
- Windows Security (JSON lines): top-level "EventID" (int) and "Computer"
  -- windows_security_parser._to_event.
- PRTG (CSV): header row containing "sensor", "status", "device" columns
  -- prtg_parser._to_event.
- SSL Certificate (CSV): header row containing "hostname", "common_name",
  "days_remaining" columns -- ssl_certificate_parser._to_event.
- Linux auth (syslog text): lines matching sshd's
  "<timestamp> <host> sshd[<pid>]: <message>" shape -- linux_auth_parser.LINE_RE.

None of this touches the database or the parser dispatch table -- it only
returns a best guess (or None if the content doesn't confidently match any
of the six signatures) for callers to act on.
"""

from __future__ import annotations

import csv
import json
import re
from io import StringIO

from apps.log_intake.models import UploadedLogFile

# Same line shape as linux_auth_parser.LINE_RE: "<ts> <host> <process>[<pid>]: <msg>".
_SSHD_LINE_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<process>[\w.\-()]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)

_PRTG_HEADER_SIGNAL = {"sensor", "status", "device"}
_SSL_HEADER_SIGNAL = {"hostname", "common_name", "days_remaining"}

# How many non-empty lines to sample for line-oriented formats (JSON lines,
# sshd text). Sampling instead of scanning the whole file keeps this cheap
# on a 5 MB upload while still being confident after a handful of lines.
_SAMPLE_LINE_COUNT = 10


def sniff_source_type(raw_text: str, file_name: str = "") -> str | None:
    """Guess a UploadedLogFile.SourceType value from real file content.

    Returns None if the content doesn't confidently match any of the six
    dedicated-parser signatures (e.g. firewall/backup/proxmox samples, or
    a file that's simply unrecognizable).
    """

    if not raw_text or not raw_text.strip():
        return None

    csv_guess = _sniff_csv(raw_text)
    if csv_guess:
        return csv_guess

    json_guess = _sniff_json_lines(raw_text)
    if json_guess:
        return json_guess

    if _sniff_linux_auth(raw_text):
        return UploadedLogFile.SourceType.LINUX

    return None


def _sniff_csv(raw_text: str) -> str | None:
    lines = raw_text.splitlines()
    first_line = lines[0] if lines else ""
    if "," not in first_line:
        return None

    try:
        header = {cell.strip().lower() for cell in next(csv.reader(StringIO(first_line)))}
    except (csv.Error, StopIteration):
        return None

    if _PRTG_HEADER_SIGNAL <= header:
        return UploadedLogFile.SourceType.PRTG
    if _SSL_HEADER_SIGNAL <= header:
        return UploadedLogFile.SourceType.SSL_CERTIFICATE

    return None


def _sniff_json_lines(raw_text: str) -> str | None:
    votes: dict[str, int] = {}

    for line in raw_text.splitlines()[:_SAMPLE_LINE_COUNT]:
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(record, dict):
            continue

        guess = _classify_json_record(record)
        if guess:
            votes[guess] = votes.get(guess, 0) + 1

    if not votes:
        return None

    return max(votes, key=votes.get)


def _classify_json_record(record: dict) -> str | None:
    if isinstance(record.get("rule"), dict) and isinstance(record.get("agent"), dict):
        return UploadedLogFile.SourceType.WAZUH

    if isinstance(record.get("EventID"), int) and "Computer" in record:
        return UploadedLogFile.SourceType.WINDOWS

    if "facility" in record and "message" in record:
        return UploadedLogFile.SourceType.GRAYLOG

    return None


def _sniff_linux_auth(raw_text: str) -> bool:
    checked = 0

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        checked += 1
        if checked > _SAMPLE_LINE_COUNT:
            break

        match = _SSHD_LINE_RE.match(line)
        if match and match.group("process") == "sshd" and match.group("pid"):
            return True

    return False
