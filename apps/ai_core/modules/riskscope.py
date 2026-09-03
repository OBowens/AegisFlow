# NOT WIRED UP -- placeholder/design-sketch only. RiskScopeModule always
# returns exactly one hardcoded gap and one hardcoded risk, regardless of
# input; its likelihood/impact are strings ("Medium") where the real
# RiskAssessment model uses a 1-5 integer scale, and "overall_risk"/
# "source: log-based" don't match the real field names/choice values at
# all. Zero callers outside the dead
# apps.ai_core.orchestrator.run_log_analysis_pipeline (see the 2026-08-24
# investigation). Do not extend without re-reading that note first -- the
# real, live risk logic lives in apps/risk/services/assessment.py.

from collections.abc import Iterable


class RiskScopeModule:
    module_name = "RiskScope AI"

    def assess_risk(self, incidents: Iterable[dict], context: dict | None = None) -> dict:
        incident_list = list(incidents)
        context = context or {}
        return {
            "module": self.module_name,
            "status": "placeholder",
            "input_summary": {
                "incident_count": len(incident_list),
                "context_keys": sorted(context.keys()),
            },
            "output": {
                "gap_findings": [
                    {
                        "gap_name": "Control validation pending",
                        "description": "Placeholder gap created until evidence checks are implemented.",
                        "affected_system": (
                            incident_list[0].get("affected_systems", ["unknown_system"])[0]
                            if incident_list
                            else "unknown_system"
                        ),
                        "source": "log-based",
                    }
                ],
                "risk_assessments": [
                    {
                        "risk_title": "Operational resilience exposure under review",
                        "likelihood": "Medium",
                        "impact": "Medium",
                        "overall_risk": "Medium",
                        "reasoning": "Placeholder risk output pending business and technical scoring logic.",
                        "recommended_priority": "Investigate and validate evidence.",
                    }
                ],
            },
            "confidence": 0.3,
            "notes": [
                "Gap discovery and risk scoring are intentionally lightweight placeholders.",
            ],
        }


def assess_risk(incidents: Iterable[dict], context: dict | None = None) -> dict:
    return RiskScopeModule().assess_risk(incidents, context=context)
