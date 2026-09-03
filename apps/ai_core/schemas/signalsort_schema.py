INCIDENT_GROUP_SCHEMA = {
    "schema": "incident_group",
    "description": "Structured incident created by grouping related alerts.",
    "fields": {
        "title": "Human-readable incident title.",
        "incident_type": "Normalized incident category.",
        "severity": "Critical, High, Medium, or Low.",
        "affected_systems": "List of systems tied to the incident.",
        "evidence_summary": "Why the related alerts were grouped together.",
    },
}
