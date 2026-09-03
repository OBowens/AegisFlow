import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aegis_agent.client import (
    SERVER_MAX_EVENTS_PER_BATCH,
    AuthError,
    IngestClient,
    PermanentError,
    TransientError,
)

GOOD_TOKEN = "good-token-value"


class _Handler(BaseHTTPRequestHandler):
    """A stand-in that mirrors the Part 1 contract closely enough to
    exercise every client branch. Behaviour is switched by the request.
    """

    def log_message(self, *args):  # silence
        pass

    def _json(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        self.server.last_headers = dict(self.headers)
        self.server.last_payload = payload

        if self.path == "/endpoints/api/enroll/":
            if payload.get("token") != GOOD_TOKEN:
                return self._json(401, {"error": "bad token"})
            name = payload.get("display_name") or "WEB-01"
            adjusted = name == "TAKEN"
            return self._json(
                200,
                {
                    "endpoint": {"id": 7, "display_name": (name + "-2") if adjusted else name, "organization": "Pilot Org"},
                    "name_was_adjusted": adjusted,
                },
            )

        if self.path == "/endpoints/api/ingest/":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer boom":
                return self._json(500, {"error": "kaboom"})
            if auth != f"Bearer {GOOD_TOKEN}":
                return self._json(401, {"error": "missing/invalid token"})
            events = payload.get("events")
            if not isinstance(events, list):
                return self._json(400, {"error": "'events' must be a list."})
            if len(events) > SERVER_MAX_EVENTS_PER_BATCH:
                return self._json(400, {"error": "batch too large"})
            for i, event in enumerate(events):
                if not all(k in event for k in ("event_type", "occurred_at", "payload")):
                    return self._json(400, {"error": f"events[{i}] missing keys"})
            return self._json(200, {"accepted": len(events)})

        return self._json(404, {"error": "no route"})


class ClientTestBase(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.last_headers = {}
        self.server.last_payload = None
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def client(self, token=GOOD_TOKEN):
        return IngestClient(self.base_url, token, timeout=5)


class EnrollTests(ClientTestBase):
    def test_happy_path(self):
        result = self.client().enroll("WIN-PILOT-01")
        self.assertEqual(result.endpoint_id, 7)
        self.assertEqual(result.display_name, "WIN-PILOT-01")
        self.assertFalse(result.name_was_adjusted)

    def test_name_was_adjusted_is_surfaced(self):
        result = self.client().enroll("TAKEN")
        self.assertTrue(result.name_was_adjusted)
        self.assertEqual(result.display_name, "TAKEN-2")

    def test_enroll_sends_token_in_body_not_header(self):
        self.client().enroll("WIN-PILOT-01")
        self.assertNotIn("Authorization", self.server.last_headers)
        self.assertEqual(self.server.last_payload["token"], GOOD_TOKEN)

    def test_bad_token_raises_auth_error(self):
        with self.assertRaises(AuthError):
            self.client(token="nope").enroll("WIN-PILOT-01")


class SendBatchTests(ClientTestBase):
    def _events(self, n=2):
        return [
            {"event_type": "Security/4688", "occurred_at": "2026-02-11T14:22:07Z", "payload": {"i": i}}
            for i in range(n)
        ]

    def test_happy_path_returns_accepted_count(self):
        self.assertEqual(self.client().send_batch(self._events(3)), 3)

    def test_authorization_header_is_exact_bearer_token(self):
        self.client().send_batch(self._events(1))
        self.assertEqual(self.server.last_headers.get("Authorization"), f"Bearer {GOOD_TOKEN}")

    def test_body_shape(self):
        self.client().send_batch(self._events(2))
        payload = self.server.last_payload
        self.assertEqual(list(payload.keys()), ["events"])
        self.assertEqual(set(payload["events"][0]), {"event_type", "occurred_at", "payload"})

    def test_401_raises_auth_error(self):
        with self.assertRaises(AuthError):
            self.client(token="wrong").send_batch(self._events(1))

    def test_400_raises_permanent_error_with_body(self):
        bad = [{"event_type": "x"}]  # missing occurred_at/payload
        with self.assertRaises(PermanentError) as ctx:
            self.client().send_batch(bad)
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("missing keys", ctx.exception.body)

    def test_500_raises_transient_error(self):
        with self.assertRaises(TransientError):
            self.client(token="boom").send_batch(self._events(1))

    def test_connection_refused_raises_transient_error(self):
        dead = IngestClient("http://127.0.0.1:9", "t", timeout=1)
        with self.assertRaises(TransientError):
            dead.send_batch(self._events(1))

    def test_client_refuses_oversized_batch_before_sending(self):
        with self.assertRaises(ValueError):
            self.client().send_batch(self._events(SERVER_MAX_EVENTS_PER_BATCH + 1))
        self.assertIsNone(self.server.last_payload)  # nothing hit the wire


if __name__ == "__main__":
    unittest.main()
