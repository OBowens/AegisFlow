import threading
import time
import unittest

from aegis_agent.service_support import (
    DEFAULT_CONFIG_PATH,
    InterruptibleSleep,
    resolve_config_path,
)


class ResolveConfigPathTests(unittest.TestCase):
    def test_default_when_nothing_supplied(self):
        self.assertEqual(resolve_config_path([], environ={}), DEFAULT_CONFIG_PATH)

    def test_explicit_flag_wins(self):
        self.assertEqual(
            resolve_config_path(["--as-service", "--config", "D:\\x.toml"], environ={}),
            "D:\\x.toml",
        )

    def test_equals_form(self):
        self.assertEqual(
            resolve_config_path(["--config=D:\\y.toml"], environ={}), "D:\\y.toml"
        )

    def test_env_var_used_when_no_flag(self):
        self.assertEqual(
            resolve_config_path([], environ={"AEGIS_AGENT_CONFIG": "E:\\z.toml"}),
            "E:\\z.toml",
        )

    def test_flag_beats_env_var(self):
        self.assertEqual(
            resolve_config_path(
                ["-c", "flag.toml"], environ={"AEGIS_AGENT_CONFIG": "env.toml"}
            ),
            "flag.toml",
        )


class InterruptibleSleepTests(unittest.TestCase):
    def test_returns_immediately_once_stopped(self):
        event = threading.Event()
        event.set()
        sleeper = InterruptibleSleep(event)
        start = time.monotonic()
        sleeper(30)
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertTrue(sleeper.stopped)

    def test_wakes_when_event_is_set_mid_sleep(self):
        event = threading.Event()
        sleeper = InterruptibleSleep(event)
        threading.Timer(0.1, event.set).start()
        start = time.monotonic()
        sleeper(30)
        self.assertLess(time.monotonic() - start, 5.0)

    def test_zero_or_negative_is_a_noop(self):
        sleeper = InterruptibleSleep(threading.Event())
        sleeper(0)
        sleeper(-1)


if __name__ == "__main__":
    unittest.main()
