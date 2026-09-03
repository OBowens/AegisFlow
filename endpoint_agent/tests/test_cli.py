import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from aegis_agent import cli
from aegis_agent.client import AuthError, EnrollResult, TransientError
from aegis_agent.filters import FilterChain


class ParserTests(unittest.TestCase):
    def test_help_exits_zero_and_lists_subcommands(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, redirect_stdout(buf):
            cli.build_parser().parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        for name in ("run", "write-config", "enroll-check", "service"):
            self.assertIn(name, buf.getvalue())

    def test_no_command_is_an_error(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args([])

    def test_run_requires_config(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["run"])

    def test_run_reports_config_error_without_traceback(self):
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = cli.main(["run", "--config", "/no/such/config.toml"])
        self.assertEqual(rc, 2)
        self.assertIn("config error", buf.getvalue())

    def test_filterchain_from_config_builds_named_rules(self):
        class Cfg:
            filters_allowlist_script_blocks = []
            filters_extra_suppress = []
            filters_disabled = []

        chain = FilterChain.from_config(Cfg())
        names = {rule.name for rule in chain.rules}
        self.assertIn("canonical_4688_system_noise", names)
        self.assertIn("empty_powershell_script_block", names)


BASE_CONFIG = """
[server]
base_url = "https://aegisflow.example.org"
enrollment_token = "tok-123"

[agent]
display_name = "WIN-PILOT-01"
"""


class EnrollCheckTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cfg = Path(self._tmp.name) / "config.toml"
        self.cfg.write_text(BASE_CONFIG)

    def _run(self, fake_enroll):
        import aegis_agent.cli as climod

        real = climod.IngestClient

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            enroll = staticmethod(fake_enroll)

        climod.IngestClient = FakeClient
        self.addCleanup(lambda: setattr(climod, "IngestClient", real))

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = climod.main(
                ["enroll-check", "--config", str(self.cfg), "--attempts", "2", "--retry-wait", "0"]
            )
        return rc, out.getvalue(), err.getvalue()

    def test_success_prints_ok_and_effective_name(self):
        rc, out, err = self._run(
            lambda name: EnrollResult(endpoint_id=7, display_name="WIN-PILOT-01", name_was_adjusted=False)
        )
        self.assertEqual(rc, 0)
        self.assertIn("OK:", out)
        self.assertIn("EFFECTIVE_NAME=WIN-PILOT-01", out)
        self.assertIn("NAME_ADJUSTED=0", out)

    def test_name_adjustment_is_reported_but_still_success(self):
        rc, out, err = self._run(
            lambda name: EnrollResult(endpoint_id=7, display_name="WIN-PILOT-01-2", name_was_adjusted=True)
        )
        self.assertEqual(rc, 0)
        self.assertIn("NAME_ADJUSTED=1", out)
        self.assertIn("EFFECTIVE_NAME=WIN-PILOT-01-2", out)
        self.assertIn("already in use", out)

    def test_auth_error_fails_without_claiming_success(self):
        def boom(name):
            raise AuthError("nope", status=401)

        rc, out, err = self._run(boom)
        self.assertEqual(rc, 3)
        self.assertNotIn("OK:", out)
        self.assertIn("FAILED", err)

    def test_unreachable_backend_fails_after_retries(self):
        def boom(name):
            raise TransientError("connection refused")

        rc, out, err = self._run(boom)
        self.assertEqual(rc, 5)
        self.assertNotIn("OK:", out)
        self.assertIn("FAILED", err)
        self.assertIn("2 attempt", err)


class EnrollCheckLiveServerTests(unittest.TestCase):
    """enroll-check driven through the real IngestClient + urllib against a
    localhost server that mimics the Part 1 enroll contract.
    """

    def setUp(self):
        import json
        import tempfile
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                token = payload.get("token")
                name = payload.get("display_name") or "X"
                if token != "good":
                    body, status = {"error": "bad token"}, 401
                else:
                    adjusted = name == "TAKEN"
                    body = {
                        "endpoint": {
                            "id": 11,
                            "display_name": (name + "-2") if adjusted else name,
                            "organization": "Pilot",
                        },
                        "name_was_adjusted": adjusted,
                    }
                    status = 200
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _config(self, token, name):
        path = self.dir / "config.toml"
        path.write_text(
            f'[server]\nbase_url = "{self.base}"\nenrollment_token = "{token}"\n'
            f'[agent]\ndisplay_name = "{name}"\n'
        )
        return str(path)

    def _run(self, token, name):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(["enroll-check", "--config", self._config(token, name)])
        return rc, out.getvalue(), err.getvalue()

    def test_live_success(self):
        rc, out, err = self._run("good", "WIN-10")
        self.assertEqual(rc, 0)
        self.assertIn("EFFECTIVE_NAME=WIN-10", out)
        self.assertIn("NAME_ADJUSTED=0", out)

    def test_live_name_collision(self):
        rc, out, err = self._run("good", "TAKEN")
        self.assertEqual(rc, 0)
        self.assertIn("EFFECTIVE_NAME=TAKEN-2", out)
        self.assertIn("NAME_ADJUSTED=1", out)

    def test_live_bad_token(self):
        rc, out, err = self._run("wrong", "WIN-10")
        self.assertEqual(rc, 3)
        self.assertNotIn("OK:", out)
        self.assertIn("401", err)


if __name__ == "__main__":
    unittest.main()
