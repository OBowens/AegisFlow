"""Command-line entry point.

Four subcommands, all thin wiring over pieces that are tested
individually:

* ``run``           -- the agent loop (enroll once, then poll/filter/spool/send).
* ``write-config``  -- render a ``config.toml`` from explicit values. The
  Part 4 installer calls this so it never has to hand-escape a display
  name into TOML.
* ``enroll-check``  -- run the existing enroll call exactly once (bounded,
  no forever-retry) and report, in a form the installer can parse,
  whether the endpoint actually reached the backend -- including the
  effective display name if the server auto-suffixed it.
* ``service``       -- Windows only; hands off to
  ``win32serviceutil.HandleCommandLine`` for install/remove/start/stop.
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import sys
import time

from .client import AuthError, EnrollResult, IngestClient, PermanentError, TransientError
from .config import ConfigError, load_config, render_config
from .filters import FilterChain
from .runner import AgentRunner, RunnerSettings
from .spool import Spool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-endpoint-agent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    run_p = sub.add_parser("run", help="run the agent loop")
    run_p.add_argument("--config", "-c", required=True, help="path to config.toml")
    run_p.add_argument(
        "--once", action="store_true", help="run a single poll/send tick, then exit"
    )
    run_p.add_argument(
        "--dry-run",
        action="store_true",
        help="read the real Event Log but never POST -- log what would be sent instead",
    )
    run_p.add_argument("--log-level", help="override logging.level from the config")

    wc_p = sub.add_parser("write-config", help="render a config.toml from explicit values")
    wc_p.add_argument("--out", "-o", required=True, help="path to write (overwritten if present)")
    wc_p.add_argument("--base-url", required=True, help="server.base_url")
    wc_p.add_argument("--token", required=True, help="server.enrollment_token")
    wc_p.add_argument("--display-name", required=True, help="agent.display_name")
    wc_p.add_argument("--state-dir", default="", help="agent.state_dir (default: next to the config)")
    wc_p.add_argument("--log-file", default="", help="logging.file (default: stderr only)")
    wc_p.add_argument("--log-level", default="INFO", help="logging.level (default: INFO)")

    ec_p = sub.add_parser(
        "enroll-check", help="enroll once and report whether the backend was reached"
    )
    ec_p.add_argument("--config", "-c", required=True, help="path to config.toml")
    ec_p.add_argument(
        "--attempts", type=int, default=3, help="max enroll attempts on a transient failure"
    )
    ec_p.add_argument(
        "--retry-wait", type=float, default=2.0, help="seconds between attempts"
    )
    ec_p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (seconds)")

    sub.add_parser(
        "service",
        help="Windows service control (install/remove/start/stop); args pass through to pywin32",
        add_help=False,
    )
    return parser


def configure_logging(level: str, log_file: str | None) -> None:
    # Under the Windows service there is no console, so sys.stderr can be
    # None -- a bare StreamHandler(None) then throws on the first record.
    handlers: list[logging.Handler] = []
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))
    if log_file:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
            )
        )
    logging.basicConfig(
        level=getattr(logging, str(level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )


class _DryRunClient:
    """Stands in for :class:`IngestClient` under ``--dry-run``: never
    touches the network, just logs.
    """

    def __init__(self, display_name: str, logger: logging.Logger):
        self._display_name = display_name
        self._log = logger

    def enroll(self, display_name: str) -> EnrollResult:
        self._log.info("[dry-run] would enroll as %r", display_name)
        return EnrollResult(endpoint_id=0, display_name=display_name, name_was_adjusted=False)

    def send_batch(self, events: list[dict]) -> int:
        self._log.info("[dry-run] would send %d event(s): %s", len(events), events)
        return len(events)


def build_runner(config, *, dry_run: bool = False, sleep=None, logger=None) -> AgentRunner:
    """Assemble the real source + filters + spool + client into an
    :class:`AgentRunner`. Shared by ``run`` and the Windows service so the
    wiring lives in exactly one place.

    ``sleep`` is injected by the service (an interruptible wait on its
    stop event) so a service stop does not have to sit through a full
    send interval.
    """
    log = logger or logging.getLogger("aegis_agent")

    from .sources.windows import WindowsEventLogSource  # lazy: needs pywin32

    source = WindowsEventLogSource()
    spool = Spool(config.state_dir, max_events=config.buffer_max_events)
    filters = FilterChain.from_config(config)
    client = (
        _DryRunClient(config.display_name, log)
        if dry_run
        else IngestClient(config.base_url, config.token)
    )

    runner = AgentRunner(
        source=source,
        filters=filters,
        spool=spool,
        client=client,
        display_name=config.display_name,
        settings=RunnerSettings(
            send_interval=config.send_interval,
            max_batch=config.max_batch,
            max_batch_bytes=config.max_batch_bytes,
        ),
        logger=log,
    )
    if sleep is not None:
        runner.sleep = sleep
    return runner


def _cmd_run(args) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    configure_logging(args.log_level or config.log_level, config.log_file)
    log = logging.getLogger("aegis_agent")

    try:
        runner = build_runner(config, dry_run=args.dry_run, logger=log)
    except RuntimeError as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 2

    try:
        runner.run_forever(max_ticks=1 if args.once else None)
    except KeyboardInterrupt:
        log.info("stopping on interrupt")
    return 0


def _cmd_write_config(args) -> int:
    from pathlib import Path

    text = render_config(
        base_url=args.base_url,
        token=args.token,
        display_name=args.display_name,
        state_dir=args.state_dir,
        log_file=args.log_file,
        log_level=args.log_level,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")

    # Fail loudly here rather than let the installer march on to a service
    # that cannot start: parse back what we just wrote.
    try:
        load_config(out, environ={})
    except ConfigError as exc:
        out.unlink(missing_ok=True)
        print(f"refused to write an invalid config: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {out}")
    return 0


def _cmd_enroll_check(args) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"FAILED: config error: {exc}", file=sys.stderr)
        return 2

    client = IngestClient(config.base_url, config.token, timeout=args.timeout)
    attempts = max(1, args.attempts)
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            result = client.enroll(config.display_name)
        except AuthError as exc:
            print(f"FAILED: the backend rejected the enrollment token (401). {exc}", file=sys.stderr)
            return 3
        except PermanentError as exc:
            print(f"FAILED: the backend refused the enrollment request: {exc}", file=sys.stderr)
            return 4
        except TransientError as exc:
            last_error = str(exc)
            if attempt < attempts:
                time.sleep(max(0.0, args.retry_wait))
            continue
        else:
            print(f"OK: connected to {config.base_url} and enrolled.")
            print(f"  endpoint id:    {result.endpoint_id}")
            print(f"  effective name: {result.display_name}")
            print(f"NAME_ADJUSTED={'1' if result.name_was_adjusted else '0'}")
            print(f"EFFECTIVE_NAME={result.display_name}")
            if result.name_was_adjusted:
                print(
                    f"  note: the name {config.display_name!r} was already in use in this "
                    f"organization; the server assigned {result.display_name!r}."
                )
            return 0

    print(
        f"FAILED: could not reach {config.base_url} after {attempts} attempt(s): {last_error}",
        file=sys.stderr,
    )
    return 5


def _cmd_service(passthrough: list[str]) -> int:
    try:
        from . import winservice
    except ImportError as exc:  # pragma: no cover - Windows-only path
        print(f"service control is only available on Windows: {exc}", file=sys.stderr)
        return 2
    return winservice.handle_command_line(passthrough)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "service":
        return _cmd_service(argv[1:])

    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "write-config":
        return _cmd_write_config(args)
    if args.command == "enroll-check":
        return _cmd_enroll_check(args)
    # argparse guarantees one of the above (required=True); "service" is
    # intercepted before parsing.
    raise AssertionError(f"unhandled command {args.command!r}")  # pragma: no cover
