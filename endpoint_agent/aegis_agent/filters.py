"""Local noise-suppression rules.

This is deliberately *not* suspicion scoring. A rule may suppress an
event only when the event, considered in isolation, is verifiably
uninteresting -- a fixed OS parent/child relationship from a
system-owned path, or an empty PowerShell script block. Anything a rule
cannot positively vouch for is kept and sent; Part 3 does the real
triage.

Every suppression carries a human-readable reason and is logged by the
runner. Nothing is dropped silently.

Residual assumption (documented, accepted): the 4688 rules trust that a
process image sitting at an exact ``C:\\Windows\\System32\\`` path with
the expected name really is the OS binary. Writing to System32 already
requires administrator rights, so a compromise deep enough to plant a
renamed binary there is past the point these rules pretend to help with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .events import (
    POWERSHELL_SCRIPT_BLOCK_EVENT_ID,
    PROCESS_CREATION_EVENT_ID,
    EventRecord,
)

SYSTEM32 = "c:\\windows\\system32"


def _norm_path(value: str | None) -> str:
    return (value or "").strip().lower().replace("/", "\\")


def _basename(value: str | None) -> str:
    path = _norm_path(value)
    _, _, tail = path.rpartition("\\")
    return tail or path


def _dirname(value: str | None) -> str:
    path = _norm_path(value)
    head, sep, _ = path.rpartition("\\")
    return head if sep else ""


def _collapse_ws(value: str | None) -> str:
    return " ".join((value or "").split())


@dataclass(frozen=True)
class FilterDecision:
    action: str  # "keep" | "suppress"
    rule: str
    reason: str


KEEP = FilterDecision("keep", "", "")


class FilterRule:
    name = "rule"

    def evaluate(self, record: EventRecord) -> str | None:
        """Return a reason string to suppress the record, or None to let
        it pass to the next rule.
        """
        raise NotImplementedError


# --- 4688: fixed OS parent/child relationships ----------------------------

@dataclass(frozen=True)
class Proc4688Spec:
    child: str                       # lower-case basename
    child_dirs: tuple[str, ...]      # allowed image directories (lower); () = any
    parents: tuple[str, ...]         # allowed full parent paths (lower); () = any
    command_line_ok: tuple[str, ...] # regexes; a non-empty command line must match one
    reason: str


# Kept intentionally short: session-0 / logon startup chain, plus the two
# high-volume runtime hosts (svchost, conhost). Each entry pins the child
# name, a system-owned directory, and -- for everything a service or user
# could plausibly spoof -- an exact parent and/or a canonical command
# line. Loosen only if a pilot shows the work queue drowning in these.
DEFAULT_4688_SPECS: tuple[Proc4688Spec, ...] = (
    Proc4688Spec("smss.exe", (SYSTEM32,), ("", "system", f"{SYSTEM32}\\smss.exe"), (), "smss.exe (session manager) under System32"),
    Proc4688Spec("csrss.exe", (SYSTEM32,), (f"{SYSTEM32}\\smss.exe",), (), "csrss.exe launched by smss.exe"),
    Proc4688Spec("wininit.exe", (SYSTEM32,), (f"{SYSTEM32}\\smss.exe",), (), "wininit.exe launched by smss.exe"),
    Proc4688Spec("winlogon.exe", (SYSTEM32,), (f"{SYSTEM32}\\smss.exe",), (), "winlogon.exe launched by smss.exe"),
    Proc4688Spec("services.exe", (SYSTEM32,), (f"{SYSTEM32}\\wininit.exe",), (), "services.exe launched by wininit.exe"),
    Proc4688Spec("lsass.exe", (SYSTEM32,), (f"{SYSTEM32}\\wininit.exe",), (), "lsass.exe launched by wininit.exe"),
    Proc4688Spec("fontdrvhost.exe", (SYSTEM32,), (f"{SYSTEM32}\\wininit.exe", f"{SYSTEM32}\\winlogon.exe"), (), "fontdrvhost.exe launched by wininit/winlogon"),
    Proc4688Spec("dwm.exe", (SYSTEM32,), (f"{SYSTEM32}\\winlogon.exe",), (), "dwm.exe launched by winlogon.exe"),
    Proc4688Spec("userinit.exe", (SYSTEM32,), (f"{SYSTEM32}\\winlogon.exe",), (), "userinit.exe launched by winlogon.exe"),
    Proc4688Spec("logonui.exe", (SYSTEM32,), (f"{SYSTEM32}\\winlogon.exe",), (), "LogonUI.exe launched by winlogon.exe"),
    Proc4688Spec(
        "svchost.exe", (SYSTEM32,), (f"{SYSTEM32}\\services.exe",),
        (r"(^|\s)-k(\s|$)",),
        "svchost.exe launched by services.exe with a -k service group",
    ),
    Proc4688Spec(
        "conhost.exe", (SYSTEM32,), (),
        (r"(?i)^\S*conhost\.exe(\s+0x[0-9a-f]+)?(\s+-forcev1)?\s*$",),
        "conhost.exe console host with canonical arguments",
    ),
    Proc4688Spec("searchprotocolhost.exe", (SYSTEM32,), (f"{SYSTEM32}\\searchindexer.exe",), (), "SearchProtocolHost.exe launched by SearchIndexer.exe"),
    Proc4688Spec("searchfilterhost.exe", (SYSTEM32,), (f"{SYSTEM32}\\searchindexer.exe",), (), "SearchFilterHost.exe launched by SearchIndexer.exe"),
)


class Canonical4688NoiseRule(FilterRule):
    name = "canonical_4688_system_noise"

    def __init__(self, specs: tuple[Proc4688Spec, ...] = DEFAULT_4688_SPECS):
        self._specs = specs

    def evaluate(self, record: EventRecord) -> str | None:
        if record.event_id != PROCESS_CREATION_EVENT_ID:
            return None
        data = record.data
        child_path = _norm_path(data.get("new_process_name"))
        if not child_path:
            return None
        child_name = _basename(child_path)
        child_dir = _dirname(child_path)
        parent_path = _norm_path(data.get("parent_process_name"))
        command_line = (data.get("command_line") or "").strip()

        for spec in self._specs:
            if child_name != spec.child:
                continue
            if spec.child_dirs and child_dir not in spec.child_dirs:
                continue
            if spec.parents and parent_path not in spec.parents:
                continue
            # A recorded command line must look canonical. An *absent*
            # command line (process-command-line auditing disabled) is
            # allowed through on the strength of the name+dir(+parent)
            # match alone.
            if spec.command_line_ok and command_line:
                if not any(re.search(rx, command_line) for rx in spec.command_line_ok):
                    continue
            return spec.reason
        return None


# --- 4104: PowerShell script-block noise ---------------------------------

class EmptyScriptBlockRule(FilterRule):
    name = "empty_powershell_script_block"

    def evaluate(self, record: EventRecord) -> str | None:
        if record.event_id != POWERSHELL_SCRIPT_BLOCK_EVENT_ID:
            return None
        if (record.data.get("script_block_text") or "").strip() == "":
            return "empty or whitespace-only PowerShell script block"
        return None


class ScriptBlockAllowlistRule(FilterRule):
    """Suppress 4104 events whose script text *exactly* matches a
    configured benign entry (whitespace-collapsed). Empty by default --
    there is no vendor-blessed list of benign script blocks, so an
    operator opts in explicitly after confirming an entry on their own
    fleet.
    """

    name = "allowlisted_powershell_script_block"

    def __init__(self, allowed_texts: tuple[str, ...] = ()):
        self._allowed = {_collapse_ws(text) for text in allowed_texts if _collapse_ws(text)}

    def evaluate(self, record: EventRecord) -> str | None:
        if record.event_id != POWERSHELL_SCRIPT_BLOCK_EVENT_ID or not self._allowed:
            return None
        if _collapse_ws(record.data.get("script_block_text")) in self._allowed:
            return "script text exactly matches a configured benign allowlist entry"
        return None


# --- operator-configured extra suppression ------------------------------

class _Matcher:
    """One entry from ``[filters] extra_suppress`` in the config file.

    All present keys must match. Keys:
      event_id, new_process_name, parent_process_name (exact, basename or
      full path, case-insensitive); command_line_contains,
      script_block_contains, path_equals (case-insensitive); reason.
    """

    def __init__(self, spec: dict):
        self.event_id = spec.get("event_id")
        self.new_process_name = _norm_path(spec.get("new_process_name")) or None
        self.parent_process_name = _norm_path(spec.get("parent_process_name")) or None
        self.command_line_contains = (spec.get("command_line_contains") or "").lower() or None
        self.script_block_contains = (spec.get("script_block_contains") or "").lower() or None
        self.path_equals = _norm_path(spec.get("path_equals")) or None
        self.reason = spec.get("reason") or "matched a configured extra_suppress rule"
        if not any(
            [
                self.event_id,
                self.new_process_name,
                self.parent_process_name,
                self.command_line_contains,
                self.script_block_contains,
                self.path_equals,
            ]
        ):
            raise ValueError("extra_suppress entry has no match conditions")

    @staticmethod
    def _name_matches(configured: str, actual: str) -> bool:
        actual = _norm_path(actual)
        return actual == configured or _basename(actual) == _basename(configured)

    def matches(self, record: EventRecord) -> bool:
        data = record.data
        if self.event_id is not None and record.event_id != self.event_id:
            return False
        if self.new_process_name and not self._name_matches(
            self.new_process_name, data.get("new_process_name", "")
        ):
            return False
        if self.parent_process_name and not self._name_matches(
            self.parent_process_name, data.get("parent_process_name", "")
        ):
            return False
        if self.command_line_contains and self.command_line_contains not in (
            data.get("command_line", "").lower()
        ):
            return False
        if self.script_block_contains and self.script_block_contains not in (
            data.get("script_block_text", "").lower()
        ):
            return False
        if self.path_equals and _norm_path(data.get("path", "")) != self.path_equals:
            return False
        return True


class ConfiguredSuppressRule(FilterRule):
    name = "configured_extra_suppression"

    def __init__(self, matchers: tuple[dict, ...] = ()):
        self._matchers = [_Matcher(entry) for entry in matchers]

    def evaluate(self, record: EventRecord) -> str | None:
        for matcher in self._matchers:
            if matcher.matches(record):
                return matcher.reason
        return None


# --- chain -------------------------------------------------------------

def build_default_rules(
    *, allowlist_texts: tuple[str, ...] = (), extra_suppress: tuple[dict, ...] = ()
) -> list[FilterRule]:
    return [
        Canonical4688NoiseRule(),
        EmptyScriptBlockRule(),
        ScriptBlockAllowlistRule(allowlist_texts),
        ConfiguredSuppressRule(extra_suppress),
    ]


@dataclass
class FilterChain:
    rules: list[FilterRule] = field(default_factory=list)
    disabled: frozenset[str] = frozenset()

    def __post_init__(self):
        self.disabled = frozenset(self.disabled)
        self.rules = [rule for rule in self.rules if rule.name not in self.disabled]

    def decide(self, record: EventRecord) -> FilterDecision:
        for rule in self.rules:
            reason = rule.evaluate(record)
            if reason:
                return FilterDecision("suppress", rule.name, reason)
        return KEEP

    @classmethod
    def from_config(cls, config) -> "FilterChain":
        return cls(
            rules=build_default_rules(
                allowlist_texts=tuple(config.filters_allowlist_script_blocks),
                extra_suppress=tuple(config.filters_extra_suppress),
            ),
            disabled=frozenset(config.filters_disabled),
        )
