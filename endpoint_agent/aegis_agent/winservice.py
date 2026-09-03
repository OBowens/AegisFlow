"""Windows service wrapper for the endpoint agent.

NOT EXERCISED BY THE TEST SUITE -- like ``sources/windows.py``, the SCM
handshake needs a real Windows host. The testable parts (config-path
resolution, the interruptible sleep) live in
:mod:`aegis_agent.service_support` and are covered on Linux.

Importing this module requires ``pywin32``; :mod:`aegis_agent.cli`
catches the ``ImportError`` on non-Windows platforms.

Verbs (via ``aegis-agent service ...``)::

    aegis-agent service install   --startup auto   # register, auto-start
    aegis-agent service start
    aegis-agent service stop
    aegis-agent service remove

The service is registered with no ``--config`` argument; it reads
``C:\\ProgramData\\AegisFlow\\agent\\config.toml`` (see
``service_support.DEFAULT_CONFIG_PATH``).
"""

from __future__ import annotations

import logging
import sys
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

from .config import ConfigError, load_config
from .service_support import InterruptibleSleep, resolve_config_path

SERVICE_NAME = "AegisFlowAgent"
SERVICE_DISPLAY_NAME = "AegisFlow Endpoint Agent"
SERVICE_DESCRIPTION = (
    "Reads a narrow slice of the Windows Event Log (process creation, "
    "PowerShell script blocks) and ships it to the AegisFlow backend."
)


class AegisAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION
    # Registered ImagePath becomes '"<exe>" --as-service', which the
    # PyInstaller entry script routes straight to run_as_service().
    _exe_args_ = "--as-service"

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop_event = threading.Event()
        self._args = list(args)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_event.set()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        try:
            self._run()
        except Exception:  # noqa: BLE001 -- last-resort: get it into the event log
            servicemanager.LogErrorMsg(
                f"{self._svc_name_} stopped on an unhandled error:\n"
                + _format_current_exception()
            )
            self.ReportServiceStatus(win32service.SERVICE_STOPPED, win32ExitCode=1)
            raise

    def _run(self):
        from .cli import build_runner, configure_logging

        config_path = resolve_config_path(self._args)
        try:
            config = load_config(config_path)
        except ConfigError as exc:
            servicemanager.LogErrorMsg(
                f"{self._svc_name_}: cannot load {config_path}: {exc}"
            )
            self.ReportServiceStatus(win32service.SERVICE_STOPPED, win32ExitCode=2)
            return

        configure_logging(config.log_level, config.log_file)
        log = logging.getLogger("aegis_agent")
        log.info("service starting from %s", config_path)

        runner = build_runner(
            config,
            sleep=InterruptibleSleep(self._stop_event),
            logger=log,
        )
        runner.run_forever(should_stop=self._stop_event.is_set)
        log.info("service stopping cleanly")


def _format_current_exception() -> str:
    import traceback

    return "".join(traceback.format_exc())


def handle_command_line(argv) -> int:
    """Back the ``aegis-agent service <verb>`` subcommand."""
    win32serviceutil.HandleCommandLine(
        AegisAgentService, argv=["aegis-agent-service", *argv]
    )
    return 0


def run_as_service() -> None:
    """Entry the frozen exe calls when the SCM launches it with no args."""
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AegisAgentService)
    servicemanager.StartServiceCtrlDispatcher()


if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) == 1:
        run_as_service()
    else:
        sys.exit(handle_command_line(sys.argv[1:]))
