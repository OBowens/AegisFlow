# NOT WIRED UP -- placeholder/design-sketch only. SignalSortModule always
# returns exactly one hardcoded incident group with severity "Medium",
# regardless of input. Zero callers outside the dead
# apps.ai_core.orchestrator.run_log_analysis_pipeline, and its output schema
# is incompatible with the current IncidentGroup model (see the 2026-08-24
# investigation). Do not extend without re-reading that note first -- the
# real, live grouping lives in apps/incidents/services/grouping.py.

from collections.abc import Iterable


class SignalSortModule:
    module_name = "SignalSort AI"

    def triage_and_group(
        self,
        parsed_alerts: Iterable[dict],
        critical_systems: list[str] | None = None,
    ) -> dict:
        alert_list = list(parsed_alerts)
        critical_systems = critical_systems or []
        incident_title = "Infrastructure or cyber event under review"
        if alert_list:
            incident_title = f"{alert_list[0].get('event_type', 'Event')} on {alert_list[0].get('affected_system', 'unknown system')}"
        return {
            "module": self.module_name,
            "status": "placeholder",
            "input_summary": {
                "parsed_alert_count": len(alert_list),
                "critical_system_count": len(critical_systems),
            },
            "output": {
                "triaged_alerts": [
                    {
                        "severity": "Medium",
                        "reason": "Placeholder severity mapping pending real triage rules.",
                        "alert": alert,
                    }
                    for alert in alert_list
                ],
                "incident_groups": [
                    {
                        "title": incident_title,
                        "incident_type": "placeholder_incident",
                        "severity": "Medium",
                        "affected_systems": list(
                            {
                                alert.get("affected_system", "unknown_system")
                                for alert in alert_list
                            }
                        )
                        or ["unknown_system"],
                        "evidence_summary": "Grouped from placeholder parsed alerts.",
                    }
                ],
            },
            "confidence": 0.25,
            "notes": [
                "Incident grouping and evidence preservation will become rule-based or model-assisted later.",
            ],
        }


def triage_and_group(parsed_alerts: Iterable[dict], critical_systems: list[str] | None = None) -> dict:
    return SignalSortModule().triage_and_group(
        parsed_alerts,
        critical_systems=critical_systems,
    )
