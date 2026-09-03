GAP_FINDING_SCHEMA = {
    "schema": "gap_finding",
    "description": "Missing control, weak evidence, or resilience weakness tied to an incident.",
    "fields": {
        "gap_name": "Short name for the missing control or weakness.",
        "description": "Why the gap matters.",
        "affected_system": "System most impacted by the gap.",
        "source": "Whether the gap came from logs, context, or user advisory input.",
    },
}

RISK_ASSESSMENT_SCHEMA = {
    "schema": "risk_assessment",
    "description": "Risk explanation generated from incidents, gaps, and organizational context.",
    "fields": {
        "risk_title": "Short title for the risk.",
        "likelihood": "Expected probability rating.",
        "impact": "Expected business or technical impact.",
        "overall_risk": "Combined risk level.",
        "reasoning": "Why the risk was scored this way.",
        "recommended_priority": "Suggested response priority.",
    },
}
