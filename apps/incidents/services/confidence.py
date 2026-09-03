"""Computes IncidentGroup.confidence from real signal already on hand at
grouping time -- each ParsedAlert's own confidence_score (set by the
per-source parser based on how well-recognized that log line's format
and pattern actually were, see apps/log_intake/services/*_parser.py) and
how much corroborating evidence exists.

This deliberately does NOT fall back to anything derived from severity,
incident type, or any other proxy -- if there's no real per-alert
confidence data to work from, it returns None, and the caller should
leave IncidentGroup.confidence unset rather than invent a number. This
is the same "don't show a confident-looking figure backed by nothing"
rule as everywhere else in the app.
"""

# A single well-recognized alert alone is exactly as confident as that
# one alert's own score -- the boost only rewards multiple alerts
# genuinely corroborating each other, capped so a large burst of
# low-quality matches can't out-vote the underlying per-alert confidence.
MAX_EVIDENCE_BOOST = 0.08
EVIDENCE_BOOST_PER_ALERT = 0.02
MAX_CORROBORATING_ALERTS_COUNTED = 4


def compute_incident_confidence(alerts):
    """`alerts` is any iterable of ParsedAlert instances (a fresh
    grouping cluster, or an incident's currently linked evidence).
    Returns a float in [0.0, 1.0], or None when there's no per-alert
    confidence_score to base a figure on at all.
    """
    scores = [alert.confidence_score for alert in alerts if alert.confidence_score is not None]
    if not scores:
        return None

    base = sum(scores) / len(scores)
    corroborating_alerts = min(len(scores) - 1, MAX_CORROBORATING_ALERTS_COUNTED)
    evidence_boost = min(corroborating_alerts * EVIDENCE_BOOST_PER_ALERT, MAX_EVIDENCE_BOOST)

    return round(min(base + evidence_boost, 1.0), 2)
