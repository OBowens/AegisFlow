PARSED_ALERT_SCHEMA = {
    "schema": "parsed_alert",
    "description": "Normalized event extracted from an uploaded log or report.",
    "fields": {
        "source_tool": "Original source system or inferred source type.",
        "timestamp": "Event timestamp if present.",
        "affected_system": "Primary asset, host, or service impacted.",
        "account": "Relevant user or service account when available.",
        "event_type": "Normalized event category.",
        "severity_clue": "Severity hint observed from the raw input.",
        "raw_message": "Original or summarized log message.",
    },
}
