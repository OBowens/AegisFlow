"""Load and validate ``config.toml`` (stdlib ``tomllib``).

The enrollment token may come from the file (``server.enrollment_token``)
or, taking precedence, the ``AEGIS_AGENT_TOKEN`` environment variable --
the Part 4 Windows service will set it that way so the secret is not
sitting in a world-readable file.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

TOKEN_ENV_VAR = "AEGIS_AGENT_TOKEN"


class ConfigError(ValueError):
    pass


def _toml_basic_string(value: str) -> str:
    """Quote ``value`` as a TOML basic string.

    Enrollment tokens are ``secrets.token_urlsafe`` output (``[A-Za-z0-9_-]``),
    but a display name is free text the operator typed, so escape the
    characters TOML's basic-string grammar requires: backslash, double
    quote, and control characters.
    """
    out = ['"']
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def render_config(
    *,
    base_url: str,
    token: str,
    display_name: str,
    state_dir: str = "",
    log_file: str = "",
    log_level: str = "INFO",
) -> str:
    """Render a ``config.toml`` body from explicit values.

    Used by ``aegis-agent write-config`` so the installer never hand-builds
    TOML. The output is deliberately the minimal set of keys the loader
    needs; every other setting keeps its documented default.
    """
    q = _toml_basic_string
    return (
        "# Written by `aegis-agent write-config` (Part 4 installer).\n"
        "# Edit by hand if you need to; the agent reloads it on restart.\n\n"
        "[server]\n"
        f"base_url = {q(base_url)}\n"
        f"enrollment_token = {q(token)}\n\n"
        "[agent]\n"
        f"display_name = {q(display_name)}\n"
        f"state_dir = {q(state_dir)}\n\n"
        "[logging]\n"
        f"level = {q(log_level)}\n"
        f"file = {q(log_file)}\n"
    )


@dataclass
class AgentConfig:
    base_url: str
    token: str
    display_name: str
    state_dir: Path
    send_interval: tuple[float, float]
    max_batch: int
    max_batch_bytes: int
    buffer_max_events: int
    log_level: str
    log_file: str | None
    filters_disabled: list[str] = field(default_factory=list)
    filters_extra_suppress: list[dict] = field(default_factory=list)
    filters_allowlist_script_blocks: list[str] = field(default_factory=list)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _interval(raw) -> tuple[float, float]:
    if raw is None:
        return (60.0, 120.0)
    _require(
        isinstance(raw, (list, tuple)) and len(raw) == 2,
        "agent.send_interval_seconds must be a two-element list [low, high]",
    )
    try:
        low, high = float(raw[0]), float(raw[1])
    except (TypeError, ValueError) as exc:
        raise ConfigError("agent.send_interval_seconds values must be numbers") from exc
    _require(0 < low <= high, "agent.send_interval_seconds must satisfy 0 < low <= high")
    return (low, high)


def load_config(path, *, environ: dict | None = None) -> AgentConfig:
    environ = os.environ if environ is None else environ
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")

    with open(path, "rb") as handle:
        try:
            raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

    server = raw.get("server", {})
    agent = raw.get("agent", {})
    logging_section = raw.get("logging", {})
    filters_section = raw.get("filters", {})

    base_url = str(server.get("base_url", "")).strip()
    token = (environ.get(TOKEN_ENV_VAR) or str(server.get("enrollment_token", "")) or "").strip()
    display_name = str(agent.get("display_name", "")).strip()

    _require(bool(base_url), "server.base_url is required")
    _require(
        base_url.startswith(("http://", "https://")),
        "server.base_url must start with http:// or https://",
    )
    _require(
        bool(token),
        f"an enrollment token is required (set server.enrollment_token or ${TOKEN_ENV_VAR})",
    )
    _require(bool(display_name), "agent.display_name is required")

    state_dir = Path(str(agent.get("state_dir", "")).strip() or (path.parent / "_agent_state"))

    extra_suppress = filters_section.get("extra_suppress", [])
    _require(isinstance(extra_suppress, list), "filters.extra_suppress must be a list of tables")
    allowlist = filters_section.get("allowlist_script_blocks", [])
    _require(isinstance(allowlist, list), "filters.allowlist_script_blocks must be a list of strings")
    disabled = filters_section.get("disabled_rules", [])
    _require(isinstance(disabled, list), "filters.disabled_rules must be a list of strings")

    return AgentConfig(
        base_url=base_url,
        token=token,
        display_name=display_name,
        state_dir=state_dir,
        send_interval=_interval(agent.get("send_interval_seconds")),
        max_batch=int(agent.get("max_batch", 250)),
        max_batch_bytes=int(agent.get("max_batch_bytes", 1_000_000)),
        buffer_max_events=int(agent.get("buffer_max_events", 50_000)),
        log_level=str(logging_section.get("level", "INFO")).upper(),
        log_file=(str(logging_section.get("file", "")).strip() or None),
        filters_disabled=[str(name) for name in disabled],
        filters_extra_suppress=list(extra_suppress),
        filters_allowlist_script_blocks=[str(text) for text in allowlist],
    )
