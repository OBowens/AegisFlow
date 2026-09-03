import tempfile
import textwrap
import unittest
from pathlib import Path

from aegis_agent.config import ConfigError, load_config

BASE = """
[server]
base_url = "https://aegisflow.example.org"
enrollment_token = "file-token"

[agent]
display_name = "WIN-PILOT-01"
"""


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, text) -> Path:
        path = self.dir / "config.toml"
        path.write_text(textwrap.dedent(text))
        return path

    def test_minimal_config(self):
        cfg = load_config(self.write(BASE), environ={})
        self.assertEqual(cfg.base_url, "https://aegisflow.example.org")
        self.assertEqual(cfg.token, "file-token")
        self.assertEqual(cfg.display_name, "WIN-PILOT-01")
        self.assertEqual(cfg.send_interval, (60.0, 120.0))
        self.assertEqual(cfg.state_dir, self.dir / "_agent_state")

    def test_env_var_overrides_file_token(self):
        cfg = load_config(self.write(BASE), environ={"AEGIS_AGENT_TOKEN": "env-token"})
        self.assertEqual(cfg.token, "env-token")

    def test_missing_file(self):
        with self.assertRaises(ConfigError):
            load_config(self.dir / "nope.toml", environ={})

    def test_invalid_toml(self):
        with self.assertRaises(ConfigError):
            load_config(self.write("this is not = valid = toml"), environ={})

    def test_missing_base_url(self):
        with self.assertRaises(ConfigError):
            load_config(self.write('[agent]\ndisplay_name = "x"\n'), environ={"AEGIS_AGENT_TOKEN": "t"})

    def test_missing_token_anywhere(self):
        with self.assertRaises(ConfigError):
            load_config(
                self.write('[server]\nbase_url="https://x"\n[agent]\ndisplay_name="x"\n'),
                environ={},
            )

    def test_bad_base_url_scheme(self):
        with self.assertRaises(ConfigError):
            load_config(
                self.write('[server]\nbase_url="ftp://x"\nenrollment_token="t"\n[agent]\ndisplay_name="x"\n'),
                environ={},
            )

    def test_bad_send_interval(self):
        text = BASE + '\nsend_interval_seconds = [120, 60]\n'
        with self.assertRaises(ConfigError):
            load_config(self.write(text), environ={})

    def test_filters_section_parsed(self):
        text = BASE + textwrap.dedent(
            """
            [filters]
            disabled_rules = ["empty_powershell_script_block"]
            allowlist_script_blocks = ["prompt"]
            extra_suppress = [{ event_id = 4688, new_process_name = "x.exe", reason = "r" }]
            """
        )
        cfg = load_config(self.write(text), environ={})
        self.assertEqual(cfg.filters_disabled, ["empty_powershell_script_block"])
        self.assertEqual(cfg.filters_allowlist_script_blocks, ["prompt"])
        self.assertEqual(cfg.filters_extra_suppress[0]["reason"], "r")


if __name__ == "__main__":
    unittest.main()
