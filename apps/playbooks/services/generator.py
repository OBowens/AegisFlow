from apps.playbooks.models import PlaybookStep, ResponsePlaybook


def create_playbooks_for_incidents(incidents):
    playbooks = []

    for incident in incidents:
        title = f"Response playbook for {incident.title}"
        playbook, created = ResponsePlaybook.objects.get_or_create(
            organization=incident.organization,
            incident=incident,
            title=title,
            defaults=_build_playbook_defaults(incident),
        )

        if not created:
            defaults = _build_playbook_defaults(incident)
            for field, value in defaults.items():
                setattr(playbook, field, value)
            playbook.save()

        _ensure_playbook_steps(playbook, incident)
        playbooks.append(playbook)

    return playbooks


def _build_playbook_defaults(incident):
    return {
        "summary": (
            f"Human-reviewed response guidance for {incident.title}. "
            "All actions require human approval before implementation."
        ),
        "immediate_steps": (
            "1. Confirm the affected system and preserve evidence.\n"
            "2. Validate whether the pattern is isolated or repeated.\n"
            "3. Notify the responsible owner or supervisor."
        ),
        "next_steps": (
            "1. Review related controls, monitoring, and continuity context.\n"
            "2. Apply the relevant SOP or response checklist.\n"
            "3. Capture status updates for leadership review."
        ),
        "escalation_steps": (
            "Escalate to the responsible system owner, operations lead, and management contact "
            "if the incident severity increases or recurrence is confirmed."
        ),
        "priority": _incident_to_priority(incident.severity),
        "status": ResponsePlaybook.Status.ACTIVE,
    }


def _ensure_playbook_steps(playbook, incident):
    step_payloads = [
        ("Confirm affected system and preserve evidence.", "System owner"),
        ("Check related logs for repeated patterns and scope.", "Analyst"),
        ("Notify the responsible owner or supervisor.", "Supervisor"),
        ("Apply the relevant SOP or checklist with human approval.", "Operations lead"),
        ("Document actions taken and observed impact.", "Recorder"),
        ("Monitor the system for recurrence or escalation.", "Monitoring team"),
    ]

    # Scoped to GENERIC steps only (not a blanket "does this playbook have
    # 6 steps" check) so this stays safe to re-run on a playbook that has
    # since had Writer-agent AI_GENERATED steps appended to it -- this
    # must never delete those.
    existing_generic_steps = list(
        playbook.steps.filter(source=PlaybookStep.Source.GENERIC).order_by("step_number", "id")
    )
    if len(existing_generic_steps) == len(step_payloads):
        return

    playbook.steps.filter(source=PlaybookStep.Source.GENERIC).delete()
    PlaybookStep.objects.bulk_create(
        [
            PlaybookStep(
                playbook=playbook,
                step_number=index,
                action=action,
                owner=owner,
                urgency=incident_to_urgency(incident.severity),
                status=PlaybookStep.Status.PENDING,
                source=PlaybookStep.Source.GENERIC,
            )
            for index, (action, owner) in enumerate(step_payloads, start=1)
        ]
    )


def _incident_to_priority(severity):
    mapping = {
        "low": ResponsePlaybook.Priority.LOW,
        "medium": ResponsePlaybook.Priority.MEDIUM,
        "high": ResponsePlaybook.Priority.HIGH,
        "critical": ResponsePlaybook.Priority.URGENT,
    }
    return mapping.get(severity, ResponsePlaybook.Priority.MEDIUM)


def incident_to_urgency(severity):
    mapping = {
        "low": PlaybookStep.Urgency.LOW,
        "medium": PlaybookStep.Urgency.MEDIUM,
        "high": PlaybookStep.Urgency.HIGH,
        "critical": PlaybookStep.Urgency.URGENT,
    }
    return mapping.get(severity, PlaybookStep.Urgency.MEDIUM)
