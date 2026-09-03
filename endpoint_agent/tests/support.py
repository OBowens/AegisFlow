"""Shared test helpers: record builders and stub collaborators."""

from __future__ import annotations

from datetime import datetime, timezone

from aegis_agent.events import EventRecord


def record_4688(
    *,
    record_id: int = 1000,
    new_process_name: str = r"C:\Windows\System32\whoami.exe",
    parent_process_name: str = r"C:\Windows\System32\cmd.exe",
    command_line: str = r'"C:\Windows\System32\whoami.exe" /priv',
    computer: str = "WIN-PILOT-01",
    occurred_at: datetime | None = None,
    **extra_data,
) -> EventRecord:
    data = {
        "new_process_name": new_process_name,
        "parent_process_name": parent_process_name,
    }
    if command_line is not None:
        data["command_line"] = command_line
    data.update(extra_data)
    return EventRecord(
        event_id=4688,
        channel="Security",
        record_id=record_id,
        occurred_at=occurred_at or datetime(2026, 2, 11, 14, 22, 7, tzinfo=timezone.utc),
        computer=computer,
        data={key: value for key, value in data.items() if value is not None},
    )


def record_4104(
    *,
    record_id: int = 2000,
    script_block_text: str = "Get-Process | Sort-Object CPU -Descending",
    computer: str = "WIN-PILOT-01",
    occurred_at: datetime | None = None,
    **extra_data,
) -> EventRecord:
    data = {"script_block_text": script_block_text, "message_number": 1, "message_total": 1}
    data.update(extra_data)
    return EventRecord(
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        record_id=record_id,
        occurred_at=occurred_at or datetime(2026, 2, 11, 14, 23, 31, tzinfo=timezone.utc),
        computer=computer,
        data=data,
    )


class StubClient:
    """Records enroll/send calls; each behaviour is scriptable."""

    def __init__(self):
        self.enroll_results = []      # list of EnrollResult | Exception
        self.send_results = []        # list of int | Exception
        self.send_attempts = []       # every send_batch call, success or not
        self.sent_batches = []        # only calls that returned (were accepted)
        self.enroll_calls = 0

    def enroll(self, display_name):
        self.enroll_calls += 1
        outcome = self.enroll_results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def send_batch(self, events):
        self.send_attempts.append(list(events))
        outcome = self.send_results.pop(0) if self.send_results else len(events)
        if isinstance(outcome, Exception):
            raise outcome
        # Only a successful call counts as "sent".
        self.sent_batches.append(list(events))
        return outcome


class FakeSleeper:
    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)
