import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from aegis_agent import cli
from aegis_agent.config import load_config, render_config


class RenderConfigTests(unittest.TestCase):
    def _roundtrip(self, **kwargs):
        text = render_config(**kwargs)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.toml"
            path.write_text(text, encoding="utf-8")
            return load_config(path, environ={})

    def test_plain_values_roundtrip(self):
        cfg = self._roundtrip(
            base_url="https://aegisflow.example.org",
            token="abc-123_XYZ",
            display_name="WIN-PILOT-01",
        )
        self.assertEqual(cfg.base_url, "https://aegisflow.example.org")
        self.assertEqual(cfg.token, "abc-123_XYZ")
        self.assertEqual(cfg.display_name, "WIN-PILOT-01")

    def test_display_name_with_quotes_and_backslashes_survives(self):
        nasty = 'Reception "front-desk" \\\\ lab-3'
        cfg = self._roundtrip(
            base_url="https://x.example.org",
            token="t",
            display_name=nasty,
        )
        self.assertEqual(cfg.display_name, nasty)

    def test_state_dir_and_log_file_passed_through(self):
        cfg = self._roundtrip(
            base_url="https://x.example.org",
            token="t",
            display_name="n",
            state_dir=r"C:\ProgramData\AegisFlow\agent",
            log_file=r"C:\ProgramData\AegisFlow\agent\agent.log",
        )
        self.assertEqual(str(cfg.state_dir), r"C:\ProgramData\AegisFlow\agent")
        self.assertEqual(cfg.log_file, r"C:\ProgramData\AegisFlow\agent\agent.log")

    def test_blank_state_dir_falls_back_to_default(self):
        cfg = self._roundtrip(
            base_url="https://x.example.org", token="t", display_name="n"
        )
        self.assertTrue(str(cfg.state_dir).endswith("_agent_state"))


class WriteConfigCommandTests(unittest.TestCase):
    def test_writes_file_and_validates_it(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "sub" / "config.toml"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(
                    [
                        "write-config",
                        "--out", str(out),
                        "--base-url", "https://aegisflow.example.org",
                        "--token", "tok",
                        "--display-name", 'Lab "A"',
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            cfg = load_config(out, environ={})
            self.assertEqual(cfg.display_name, 'Lab "A"')

    def test_bad_base_url_is_rejected_at_write_time(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "config.toml"
            rc = cli.main(
                [
                    "write-config",
                    "--out", str(out),
                    "--base-url", "ftp://nope",
                    "--token", "tok",
                    "--display-name", "n",
                ]
            )
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
