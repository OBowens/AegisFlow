import csv
import ipaddress
import json
import re
from datetime import datetime, time
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from apps.log_intake.models import ParsedAlert, UploadedLogFile


MAX_EVENTS = 50
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CRITICAL_TERMS = (
    "critical",
    "emergency",
    "ransomware",
    "malware",
    "compromised",
    "data exfiltration",
)
HIGH_TERMS = (
    "failed login",
    "brute force",
    "backup failed",
    "authentication failure",
    "error",
    "denied repeatedly",
)
MEDIUM_TERMS = ("warning", "denied", "unavailable", "timeout", "degraded")


def parse_uploaded_log(uploaded_log_file: UploadedLogFile) -> list[ParsedAlert]:
    existing_alerts = list(uploaded_log_file.parsed_alerts.order_by("id"))
    if existing_alerts:
        return existing_alerts

    file_path = _resolve_storage_path(uploaded_log_file.storage_path)

    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
        event_payloads = _extract_event_payloads(
            raw_text=raw_text,
            source_type=uploaded_log_file.source_type,
            file_suffix=file_path.suffix.lower(),
        )

        created_alerts: list[ParsedAlert] = []

        for payload in event_payloads[:MAX_EVENTS]:
            normalized = _normalize_payload(payload, uploaded_log_file)
            created_alerts.append(
                ParsedAlert.objects.create(
                    organization=uploaded_log_file.organization,
                    uploaded_file=uploaded_log_file,
                    source_tool=uploaded_log_file.source_type,
                    timestamp=normalized["timestamp"],
                    affected_system=normalized["affected_system"],
                    account=normalized["account"],
                    source_ip=normalized["source_ip"],
                    destination_ip=normalized["destination_ip"],
                    event_type=normalized["event_type"],
                    severity_hint=normalized["severity_hint"],
                    raw_message=normalized["raw_message"],
                    normalized_summary=normalized["normalized_summary"],
                )
            )

        return created_alerts
    except Exception:
        uploaded_log_file.status = UploadedLogFile.Status.FAILED
        uploaded_log_file.save(update_fields=["status"])
        return []


def _resolve_storage_path(storage_path: str) -> Path:
    path = Path(storage_path)
    if path.is_absolute():
        return path

    private_root_candidate = Path(settings.PRIVATE_UPLOAD_ROOT) / path
    if private_root_candidate.exists():
        return private_root_candidate

    return Path(settings.BASE_DIR) / path


def _extract_event_payloads(raw_text: str, source_type: str, file_suffix: str) -> list:
    parse_mode = source_type
    if file_suffix == ".json":
        parse_mode = "json"
    elif file_suffix == ".csv":
        parse_mode = "csv"

    if parse_mode == "json":
        events = _parse_json_events(raw_text)
        if events:
            return events

    if parse_mode == "csv":
        events = _parse_csv_events(raw_text)
        if events:
            return events

    return _parse_text_events(raw_text)


def _parse_json_events(raw_text: str) -> list:
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError:
        return _parse_text_events(raw_text)

    if isinstance(loaded, list):
        return loaded

    if isinstance(loaded, dict):
        for key in ("events", "alerts", "records", "items", "results", "logs", "data"):
            candidate = loaded.get(key)
            if isinstance(candidate, list):
                return candidate
        return [loaded]

    return _parse_text_events(raw_text)


def _parse_csv_events(raw_text: str) -> list:
    try:
        reader = csv.DictReader(StringIO(raw_text))
        if reader.fieldnames:
            rows = [row for row in reader if any((value or "").strip() for value in row.values())]
            if rows:
                return rows
    except csv.Error:
        pass

    try:
        reader = csv.reader(StringIO(raw_text))
        rows = []
        for row in reader:
            if not row:
                continue
            joined = ", ".join(cell.strip() for cell in row if cell and cell.strip())
            if joined:
                rows.append({"raw_message": joined})
        return rows
    except csv.Error:
        return _parse_text_events(raw_text)


def _parse_text_events(raw_text: str) -> list:
    return [line.strip() for line in raw_text.splitlines() if line.strip()]


def _normalize_payload(payload, uploaded_log_file: UploadedLogFile) -> dict:
    if isinstance(payload, dict):
        message = _dict_value(
            payload,
            "raw_message",
            "message",
            "msg",
            "summary",
            "description",
            "event",
            "log",
            "text",
        ) or json.dumps(payload, ensure_ascii=False)
        affected_system = _dict_value(
            payload,
            "affected_system",
            "host",
            "hostname",
            "system",
            "device",
            "asset",
            "vm",
            "host_name",
            "computer",
        )
        account = _dict_value(
            payload,
            "account",
            "user",
            "username",
            "principal",
            "owner",
            "user_name",
        )
        source_ip = _safe_ip(
            _dict_value(
                payload,
                "source_ip",
                "src_ip",
                "client_ip",
                "ip",
                "source",
                "sourceAddress",
            )
        )
        destination_ip = _safe_ip(
            _dict_value(
                payload,
                "destination_ip",
                "dst_ip",
                "server_ip",
                "destination",
                "destinationAddress",
            )
        )
        event_type = _dict_value(payload, "event_type", "type", "action", "category", "event_name")
        timestamp = _parse_timestamp(
            _dict_value(payload, "timestamp", "time", "event_time", "datetime", "date")
        )
    else:
        message = str(payload)
        affected_system = None
        account = ""
        source_ip = None
        destination_ip = None
        event_type = None
        timestamp = _parse_timestamp_from_text(message)

    message = (message or "").strip()
    affected_system = affected_system or _detect_system_from_text(message) or "Unknown system"
    source_ip = source_ip or _detect_ips_from_text(message)[0]
    destination_ip = destination_ip or _detect_ips_from_text(message)[1]
    event_type = event_type or _detect_event_type(message)
    severity_hint = _detect_severity(message)

    summary = f"{event_type.replace('_', ' ').title()} detected for {affected_system}."
    if message:
        summary = f"{summary} {message[:120]}"

    return {
        "timestamp": timestamp,
        "affected_system": affected_system,
        "account": account or "",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity_hint": severity_hint,
        "raw_message": message,
        "normalized_summary": summary[:255],
    }


def _dict_value(payload: dict, *keys: str):
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _detect_severity(text: str) -> str:
    lowered = text.lower()
    if any(term in lowered for term in CRITICAL_TERMS):
        return ParsedAlert.SeverityHint.CRITICAL
    if any(term in lowered for term in HIGH_TERMS):
        return ParsedAlert.SeverityHint.HIGH
    if any(term in lowered for term in MEDIUM_TERMS):
        return ParsedAlert.SeverityHint.MEDIUM
    return ParsedAlert.SeverityHint.LOW


def _detect_event_type(text: str) -> str:
    lowered = text.lower()
    if (
        "failed login" in lowered
        or "brute force" in lowered
        or "authentication failure" in lowered
    ):
        return "authentication_failure"
    if "backup failed" in lowered:
        return "backup_failure"
    if "malware" in lowered or "ransomware" in lowered or "compromised" in lowered:
        return "malware_activity"
    if (
        "unavailable" in lowered
        or "timeout" in lowered
        or "degraded" in lowered
        or "outage" in lowered
    ):
        return "availability_issue"
    if "denied" in lowered and "firewall" in lowered:
        return "firewall_denied"
    if "warning" in lowered:
        return "warning_event"
    if "firewall" in lowered:
        return "firewall_event"
    if "certificate" in lowered or "ssl" in lowered:
        return "certificate_event"
    return "log_event"


def _detect_system_from_text(text: str) -> str | None:
    match = re.search(r"\b(host|server|system|vm|device)[:=\s-]+([A-Za-z0-9_.-]+)", text, re.IGNORECASE)
    if match:
        return match.group(2)
    return None


def _detect_ips_from_text(text: str) -> tuple[str | None, str | None]:
    matches = [ip for ip in IP_PATTERN.findall(text) if _safe_ip(ip)]
    if not matches:
        return None, None
    if len(matches) == 1:
        return matches[0], None
    return matches[0], matches[1]


def _safe_ip(value: str | None) -> str | None:
    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _parse_timestamp(value: str | None):
    if not value:
        return None

    parsed_datetime = parse_datetime(value)
    if parsed_datetime:
        if timezone.is_naive(parsed_datetime):
            return timezone.make_aware(parsed_datetime, timezone.get_current_timezone())
        return parsed_datetime

    parsed_date = parse_date(value)
    if parsed_date:
        combined = datetime.combine(parsed_date, time.min)
        return timezone.make_aware(combined, timezone.get_current_timezone())

    return None


def _parse_timestamp_from_text(text: str):
    match = re.search(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z)?\b", text)
    if match:
        return _parse_timestamp(match.group(0).replace("Z", "+00:00"))
    return None
