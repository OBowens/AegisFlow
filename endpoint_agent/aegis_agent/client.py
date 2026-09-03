"""HTTP client for the two agent-facing endpoints.

``urllib`` only -- the backend itself talks to Anthropic over ``urllib``
with no SDK, and keeping the agent dependency-free matters for the Part 4
Windows packaging.

Error taxonomy the runner depends on:

* ``TransientError``  -- network failure, timeout, 5xx, 429, unparseable
  response. Retry the same payload later with backoff; keep the events.
* ``AuthError``       -- 401. The token is wrong or revoked; retrying the
  same payload will not help, but the events are still valid -- keep
  them buffered and back off hard.
* ``PermanentError``  -- other 4xx (typically 400). The payload itself is
  malformed. Quarantine it; do not retry.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

# Mirrors apps/endpoints/views.py::MAX_EVENTS_PER_BATCH. The Django-side
# contract test (apps/endpoints/tests_agent_payload_contract.py) asserts
# these two stay in step.
SERVER_MAX_EVENTS_PER_BATCH = 500

DEFAULT_TIMEOUT = 30
USER_AGENT = "aegis-endpoint-agent"

ENROLL_PATH = "/endpoints/api/enroll/"
INGEST_PATH = "/endpoints/api/ingest/"


class ClientError(Exception):
    pass


class TransientError(ClientError):
    pass


class PermanentError(ClientError):
    def __init__(self, message: str, *, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class AuthError(PermanentError):
    pass


@dataclass(frozen=True)
class EnrollResult:
    endpoint_id: int
    display_name: str
    name_was_adjusted: bool


def _read_body(source, limit: int = 4096) -> str:
    try:
        return source.read(limit).decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""


class IngestClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = DEFAULT_TIMEOUT, opener=None):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener()

    def enroll(self, display_name: str) -> EnrollResult:
        body = self._post(
            ENROLL_PATH, {"token": self._token, "display_name": display_name}, auth=False
        )
        try:
            endpoint = body["endpoint"]
            return EnrollResult(
                endpoint_id=int(endpoint["id"]),
                display_name=str(endpoint["display_name"]),
                name_was_adjusted=bool(body.get("name_was_adjusted", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TransientError(f"enroll response was not in the expected shape: {body!r}") from exc

    def send_batch(self, events: list[dict]) -> int:
        if len(events) > SERVER_MAX_EVENTS_PER_BATCH:
            raise ValueError(
                f"refusing to send {len(events)} events; server cap is {SERVER_MAX_EVENTS_PER_BATCH}"
            )
        body = self._post(INGEST_PATH, {"events": events}, auth=True)
        try:
            return int(body["accepted"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransientError(f"ingest response was not in the expected shape: {body!r}") from exc

    # -- internals --------------------------------------------------

    def _post(self, path: str, payload: dict, *, auth: bool) -> dict:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        if auth:
            request.add_header("Authorization", f"Bearer {self._token}")

        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = _read_body(exc)
            if status == 401:
                raise AuthError(f"{path} rejected the token (401)", status=401, body=body) from exc
            if status == 429 or 500 <= status < 600:
                raise TransientError(f"{path} returned HTTP {status}") from exc
            raise PermanentError(f"{path} returned HTTP {status}", status=status, body=body) from exc
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            raise TransientError(f"{path} is unreachable: {exc}") from exc

        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise TransientError(f"{path} returned a non-JSON body") from exc
