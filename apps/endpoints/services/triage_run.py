"""One correlation + AI-triage pass over recent endpoint events.

Called by ``manage.py triage_endpoint_events`` (a thin wrapper) on an
interval via host cron. Kept as a service function so it is testable
without the command.

Flow per run:

1. Run the deterministic correlation rules over unscanned events
   (:func:`apps.endpoints.services.correlation.find_correlation_candidates`).
2. Persist each flagged cluster as an ``EndpointCorrelationCandidate``
   (``PENDING``) and mark every scanned event so it is not re-processed
   -- one atomic step.
3. Build a triage worklist: previously failed / rate-limited candidates
   first, then the new ``PENDING`` ones, capped at ``max_candidates`` so
   one run cannot exhaust the shared hourly AI budget.
4. Triage each: ``deny_ai_call`` gate -> ``AIRun`` -> ``run_endpoint_triage``.
   * verdict ``escalate`` -> create an ``IncidentGroup`` (it surfaces in
     the existing work queue with no special-casing).
   * verdict ``benign`` -> candidate ``BENIGN``, no incident.
   * provider error / unparseable verdict -> candidate ``TRIAGE_FAILED``
     (``ai_*`` left blank -- an honest "not yet triaged"), retried next
     run, then ``ABANDONED`` ("manual check required") after
     ``MAX_TRIAGE_ATTEMPTS``.
   * rate-limited -> candidate ``RATE_LIMITED``, retried next run,
     **not** counted against the attempt cap (a systemic throttle, not
     this candidate's fault).

Never fabricates: a verdict/severity is written only from a real
completed call, and a candidate is never silently dropped.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.ai_core.modules.endpoint_triage import run_endpoint_triage
from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun, AuditLog
from apps.endpoints.models import EndpointCorrelationCandidate, EndpointEvent
from apps.endpoints.services.correlation import find_correlation_candidates
from apps.endpoints.services.escalation import escalate_candidate
from apps.organizations.services.current_organization import get_current_organization

AI_MODULE = "endpoint_triage"
DEFAULT_MAX_CANDIDATES = 8

# The 40/hr global AI budget (apps/ai_core/rate_limit.py) is shared with
# the interactive, human-in-the-loop modules -- analyst, App Assistant,
# etc. Background batch triage yields to them: when the rolling hour's AI
# usage is within this many calls of the global cap, a run triages
# nothing new and leaves candidates PENDING for the next run (10 min
# later). Env-overridable; 0 disables the reserve.
DEFAULT_INTERACTIVE_RESERVE = 15
_HOUR_SECONDS = 3600

_LOG = logging.getLogger("apps.endpoints.triage")

_Status = EndpointCorrelationCandidate.Status


@dataclass
class TriageRunReport:
    scanned_events: int = 0
    candidates_created: int = 0
    triaged_escalated: int = 0
    triaged_benign: int = 0
    triage_failed: int = 0
    rate_limited: int = 0
    abandoned: int = 0
    deferred_for_headroom: int = 0
    incidents_created: list[int] = field(default_factory=list)
    incidents_updated: list[int] = field(default_factory=list)
    overflowed: bool = False
    dry_run: bool = False

    def as_summary(self) -> str:
        return (
            f"scanned {self.scanned_events} event(s), "
            f"{self.candidates_created} new candidate(s); "
            f"escalated={self.triaged_escalated} benign={self.triaged_benign} "
            f"failed={self.triage_failed} rate_limited={self.rate_limited} "
            f"abandoned={self.abandoned}"
            + (f"; new incidents={self.incidents_created}" if self.incidents_created else "")
            + (f"; updated incidents={self.incidents_updated}" if self.incidents_updated else "")
            + (
                f"; deferred={self.deferred_for_headroom} (AI budget reserved for interactive use)"
                if self.deferred_for_headroom
                else ""
            )
            + ("; DRY RUN (nothing written)" if self.dry_run else "")
            + ("; scan hit the per-run event cap" if self.overflowed else "")
        )


def run_triage_scan(
    *,
    provider=None,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    now=None,
    dry_run: bool = False,
    logger: logging.Logger | None = None,
) -> TriageRunReport:
    now = now or timezone.now()
    log = logger or _LOG

    scan = find_correlation_candidates(now=now)
    report = TriageRunReport(
        scanned_events=len(scan.scanned_event_ids),
        candidates_created=len(scan.candidates),
        overflowed=scan.overflowed,
        dry_run=dry_run,
    )

    if dry_run:
        for spec in scan.candidates:
            log.info(
                "[dry-run] candidate: endpoint=%s events=%d\n%s",
                spec.endpoint.display_name,
                len(spec.events),
                spec.trigger_summary,
            )
        log.info("[dry-run] %s", report.as_summary())
        return report

    _persist_candidates_and_mark_scanned(scan, now)

    worklist = _build_worklist(max_candidates)
    headroom = _interactive_headroom(now)
    capacity = min(len(worklist), max(0, headroom))
    if capacity < len(worklist):
        report.deferred_for_headroom = len(worklist) - capacity
        log.info(
            "deferring %d candidate(s) this run: shared AI budget reserved for interactive "
            "use (headroom=%d); they stay PENDING for the next run",
            report.deferred_for_headroom,
            headroom,
        )

    for candidate in worklist[:capacity]:
        try:
            _triage_one(candidate, provider=provider, report=report, log=log)
        except Exception:  # pragma: no cover - defensive; RuntimeError is handled inside
            log.exception("unexpected error triaging candidate %s", candidate.id)

    AuditLog.objects.create(
        organization=get_current_organization(),
        user=None,
        action="endpoint_triage_scan",
        target_type="EndpointCorrelationCandidate",
        target_id="",
        details=report.as_summary(),
    )
    log.info("endpoint triage scan complete: %s", report.as_summary())
    return report


def _persist_candidates_and_mark_scanned(scan, now) -> None:
    with transaction.atomic():
        for spec in scan.candidates:
            candidate = EndpointCorrelationCandidate.objects.create(
                endpoint=spec.endpoint,
                organization=spec.organization,
                first_event_at=spec.first_event_at,
                last_event_at=spec.last_event_at,
                event_count=len(spec.events),
                trigger_summary=spec.trigger_summary,
                status=_Status.PENDING,
            )
            EndpointEvent.objects.filter(
                id__in=[event.id for event in spec.events]
            ).update(candidate=candidate)

        if scan.scanned_event_ids:
            EndpointEvent.objects.filter(id__in=scan.scanned_event_ids).update(
                correlation_scanned_at=now
            )


def _build_worklist(max_candidates: int) -> list[EndpointCorrelationCandidate]:
    retryable = list(
        EndpointCorrelationCandidate.objects.filter(
            status__in=[_Status.TRIAGE_FAILED, _Status.RATE_LIMITED],
            attempt_count__lt=EndpointCorrelationCandidate.MAX_TRIAGE_ATTEMPTS,
        )
        .select_related("endpoint", "organization")
        .order_by("created_at")
    )
    pending = list(
        EndpointCorrelationCandidate.objects.filter(status=_Status.PENDING)
        .select_related("endpoint", "organization")
        .order_by("created_at")
    )
    return (retryable + pending)[: max(0, max_candidates)]


def _interactive_headroom(now) -> int:
    """Calls still available in the shared rolling-hour AI budget, minus
    the reserve kept free for interactive modules.

    Mirrors the count in apps/ai_core/rate_limit.py exactly (same table,
    same 60-minute window, same non-billable exclusion) -- reading it,
    not changing it. A very large number means the limiter is off.
    """
    if not getattr(settings, "AI_RATE_LIMIT_ENABLED", True):
        return 10**9
    cap = int(getattr(settings, "AI_RATE_LIMIT_GLOBAL_PER_HOUR", 40))
    if cap <= 0:
        return 10**9
    reserve = int(getattr(settings, "AI_TRIAGE_INTERACTIVE_RESERVE", DEFAULT_INTERACTIVE_RESERVE))
    used = (
        AIRun.objects.filter(created_at__gte=now - timedelta(seconds=_HOUR_SECONDS))
        .exclude(ai_module="demo_log_workflow")
        .count()
    )
    return cap - used - reserve


def _triage_one(candidate, *, provider, report: TriageRunReport, log) -> None:
    denied = deny_ai_call(candidate.organization, AI_MODULE)
    if denied:
        # deny_ai_call already wrote an AIRun FAILED row. A throttle is
        # not this candidate's fault -- don't spend an attempt on it.
        candidate.status = _Status.RATE_LIMITED
        candidate.ai_error = denied
        candidate.save(update_fields=["status", "ai_error", "updated_at"])
        report.rate_limited += 1
        return

    ai_run = AIRun.objects.create(
        organization=candidate.organization,
        ai_module=AI_MODULE,
        input_type="EndpointCorrelationCandidate",
        input_id=str(candidate.id),
        output_type="IncidentGroup",
        output_id="",
        status=AIRun.Status.STARTED,
    )
    candidate.attempt_count += 1

    try:
        result = run_endpoint_triage(candidate, provider=provider)
    except RuntimeError as exc:
        with transaction.atomic():
            candidate.status = _Status.TRIAGE_FAILED
            candidate.ai_error = str(exc)
            candidate.triaged_at = None
            _abandon_if_exhausted(candidate)
            candidate.save(
                update_fields=["status", "ai_error", "triaged_at", "attempt_count", "updated_at"]
            )
            ai_run.status = AIRun.Status.FAILED
            ai_run.error_message = str(exc)
            ai_run.save(update_fields=["status", "error_message"])
        report.triage_failed += 1
        if candidate.status == _Status.ABANDONED:
            report.abandoned += 1
            log.warning(
                "candidate %s abandoned after %d failed triage attempt(s); manual check required",
                candidate.id,
                candidate.attempt_count,
            )
        return

    # One transaction for the whole success write, so a mid-write failure
    # leaves the candidate PENDING (cleanly retried next run) rather than
    # half-updated with a duplicate incident risk.
    candidate.ai_verdict = result["verdict"]
    candidate.ai_severity = result["severity"]
    candidate.ai_summary = result["summary"]
    candidate.ai_reasoning = result["reasoning"]
    candidate.ai_model = result["model"]
    candidate.ai_error = ""
    candidate.triaged_at = timezone.now()
    ai_run.model_used = result["model"]

    incident = None
    incident_created = False
    with transaction.atomic():
        if result["verdict"] == "escalate":
            incident, incident_created = escalate_candidate(candidate, result)
            candidate.status = _Status.ESCALATED
            candidate.save()
            ai_run.status = AIRun.Status.SUCCESS
            ai_run.output_id = str(incident.id)
            ai_run.save(update_fields=["status", "model_used", "output_id"])
        else:
            candidate.status = _Status.BENIGN
            candidate.save()
            ai_run.status = AIRun.Status.SUCCESS
            ai_run.output_type = ""
            ai_run.output_id = ""
            ai_run.save(update_fields=["status", "model_used", "output_type", "output_id"])

    if incident is None:
        report.triaged_benign += 1
        return
    report.triaged_escalated += 1
    if incident_created:
        report.incidents_created.append(incident.id)
    elif incident.id not in report.incidents_updated:
        report.incidents_updated.append(incident.id)


def _abandon_if_exhausted(candidate) -> None:
    if candidate.attempt_count >= EndpointCorrelationCandidate.MAX_TRIAGE_ATTEMPTS:
        candidate.status = _Status.ABANDONED
