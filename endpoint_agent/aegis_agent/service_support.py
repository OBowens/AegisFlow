"""Stdlib-only helpers for the Windows service wrapper.

Split out of :mod:`aegis_agent.winservice` so the parts that do not touch
``pywin32`` -- config-path resolution and the interruptible sleep the
service injects into the runner -- are unit-tested on the Linux dev box.
``winservice`` itself (the SCM handshake) stays manual-verification-only,
like ``sources/windows.py``.
"""

from __future__ import annotations

import os
import threading

# Baked into the installer; the service is always registered with no
# ``--config`` argument and finds its config here. Overridable for tests
# and odd deployments via the env var or an explicit argv flag.
DEFAULT_CONFIG_PATH = r"C:\ProgramData\AegisFlow\agent\config.toml"
CONFIG_ENV_VAR = "AEGIS_AGENT_CONFIG"


def resolve_config_path(argv=None, environ=None) -> str:
    """Where the service should read ``config.toml`` from.

    Precedence: an explicit ``--config PATH`` / ``--config=PATH`` in
    ``argv`` (pywin32 passes the service's registered args here), then
    ``$AEGIS_AGENT_CONFIG``, then :data:`DEFAULT_CONFIG_PATH`.
    """
    argv = list(argv or [])
    for i, arg in enumerate(argv):
        if arg in ("--config", "-c") and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--config="):
            return arg.split("=", 1)[1]
        if arg.startswith("-c="):
            return arg.split("=", 1)[1]
    environ = os.environ if environ is None else environ
    return environ.get(CONFIG_ENV_VAR) or DEFAULT_CONFIG_PATH


class InterruptibleSleep:
    """A drop-in replacement for ``time.sleep`` that returns early once a
    stop has been signalled.

    The runner sleeps a full ``send_interval`` (up to ~2 min) between
    ticks. Handing it one of these instead means a service stop is
    observed within one poll, not one interval.
    """

    def __init__(self, stop_event: threading.Event):
        self._stop = stop_event

    def __call__(self, seconds: float) -> None:
        if seconds and seconds > 0:
            self._stop.wait(seconds)

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()
