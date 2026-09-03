# NOT WIRED UP -- placeholder/design-sketch only. PlaybookPilotModule
# returns generic canned step text with only the incident title
# interpolated in. Zero callers outside the dead
# apps.ai_core.orchestrator.run_log_analysis_pipeline; its output uses
# "escalation_path" and "later_steps", neither of which exist on the real
# ResponsePlaybook model, which instead has "escalation_steps" and a
# separate related PlaybookStep table this module never populates (see the
# 2026-08-24 investigation). Do not extend without re-reading that note
# first -- the real, live playbook generation lives in
# apps/playbooks/services/generator.py.


class PlaybookPilotModule:
    module_name = "PlaybookPilot AI"

    def generate_playbook(
        self,
        incident: dict,
        risks: list[dict] | None = None,
        readiness_findings: list[dict] | None = None,
    ) -> dict:
        risks = risks or []
        readiness_findings = readiness_findings or []
        return {
            "module": self.module_name,
            "status": "placeholder",
            "input_summary": {
                "incident_title": incident.get("title", "Unknown incident"),
                "risk_count": len(risks),
                "readiness_finding_count": len(readiness_findings),
            },
            "output": {
                "playbook_title": f"Response plan for {incident.get('title', 'incident under review')}",
                "immediate_steps": [
                    "Validate the incident scope with the relevant owner.",
                    "Preserve evidence before making manual remediation changes.",
                ],
                "next_steps": [
                    "Review the mapped risks and continuity impacts.",
                    "Decide whether to trigger a formal SOP or escalation path.",
                ],
                "later_steps": [
                    "Capture lessons learned and update the checklist library.",
                ],
                "escalation_path": "Escalate through the organization contact chain defined for the affected system.",
            },
            "confidence": 0.35,
            "notes": [
                "Playbooks are recommendations only. No automatic remediation is triggered.",
            ],
        }


def generate_playbook(
    incident: dict,
    risks: list[dict] | None = None,
    readiness_findings: list[dict] | None = None,
) -> dict:
    return PlaybookPilotModule().generate_playbook(
        incident,
        risks=risks,
        readiness_findings=readiness_findings,
    )
