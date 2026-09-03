"""Deterministic approval gate for recommended/playbook action text.

No AI call, no model state involved -- this is a pure text scan that
flags an action as describing a destructive or state-changing operation
(disabling an account, blocking an IP, restarting a server, deleting
something, a firewall/access change, etc.) that should not be taken
without a human approving it first.

Being a pure function of already-persisted text (PlaybookStep.action
never changes after creation), the flag is computed at render time
rather than stored on PlaybookStep -- there's nothing to keep in sync,
and it stays correct automatically if this term list is ever tightened
or widened later.

The term list intentionally errs toward over-flagging: a false positive
just means a human glances at something that turned out to be fine; a
missed destructive action getting no oversight is the failure mode this
exists to prevent.
"""

DESTRUCTIVE_ACTION_TERMS = (
    "disable",
    "block",
    "restart",
    "reboot",
    "shut down",
    "shutdown",
    "power off",
    "restore",
    "delete",
    "isolate",
    "quarantine",
    "revoke",
    "terminate",
    "suspend",
    "lock",
    "wipe",
    "reimage",
    "reset",
    "contain",
    "firewall rule",
    "firewall change",
    "firewall configuration",
    "access change",
    "deny access",
    "revoke access",
    "remove access",
    "restrict access",
    "kill process",
    "kill session",
)


def requires_human_approval(action_text: str) -> bool:
    """True if `action_text` describes a destructive/state-changing action
    (account, system, or network change) that should not be taken without
    a human approving it first."""
    lowered = (action_text or "").lower()
    return any(term in lowered for term in DESTRUCTIVE_ACTION_TERMS)
