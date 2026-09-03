# Same relative weighting as the old flat-penalty formula (critical
# weighted heaviest, then high, then medium; low findings aren't counted,
# matching prior behavior).
CRITICAL_WEIGHT = 8
HIGH_WEIGHT = 5
MEDIUM_WEIGHT = 3


def compute_readiness_score(*, critical_count: int = 0, high_count: int = 0, medium_count: int = 0) -> int:
    """Weighted proportion of critical/high/medium findings, scaled to
    0-100, instead of an unbounded flat penalty per finding.

    The old `max(0, 100 - critical*8 - high*5 - medium*3)` formula floored
    at 0 permanently once volume alone pushed the subtraction past 100
    (around 13 critical findings), regardless of the mix. This normalizes
    against the total finding count, so the score reflects how bad the
    *composition* of findings is (what fraction of them are critical vs.
    high vs. medium), not how many there happen to be -- it can only reach
    0 when every single finding is critical.
    """
    total_findings = critical_count + high_count + medium_count
    if total_findings <= 0:
        return 100

    weighted_bad = (
        critical_count * CRITICAL_WEIGHT
        + high_count * HIGH_WEIGHT
        + medium_count * MEDIUM_WEIGHT
    )
    worst_case_bad = total_findings * CRITICAL_WEIGHT

    score = round(100 * (1 - weighted_bad / worst_case_bad))
    return max(0, min(100, score))


# Chart geometry constants (SVG user units, viewBox="0 0 100 32").
_TREND_WIDTH = 100
_TREND_HEIGHT = 32
_TREND_PAD_TOP = 2
_TREND_PAD_BOTTOM = 2


def build_readiness_trend(snapshots) -> dict:
    """Build a small, honest line/area chart's geometry from real
    ReadinessScoreSnapshot rows, ordered oldest to newest.

    Fixed 0-100 y-scale -- never autoscaled to the observed min/max --
    so a narrow real fluctuation (e.g. 96 to 98) isn't visually
    exaggerated into looking like a bigger swing than it actually is.

    With 0 points there's nothing to plot. With exactly 1 point, only a
    single marker is returned -- no line, since there is nothing to
    connect it to; rendering a flat line across the full width would
    imply a history that doesn't exist yet. With 2+, every real score is
    plotted in order, evenly spaced along x by sequence (not by elapsed
    time) -- simple and honest about the values themselves without
    implying a false precision about exact timing.
    """
    scores = [snapshot.score for snapshot in snapshots]
    points = [{"score": snapshot.score, "computed_at": snapshot.computed_at} for snapshot in snapshots]
    count = len(scores)

    if count == 0:
        return {
            "has_data": False,
            "is_single_point": False,
            "points": [],
            "point_count": 0,
            "latest_score": None,
            "marker": None,
            "polyline": "",
            "area_path": "",
        }

    plot_height = _TREND_HEIGHT - _TREND_PAD_TOP - _TREND_PAD_BOTTOM

    def y_for(score):
        return _TREND_PAD_TOP + plot_height * (1 - score / 100)

    if count == 1:
        marker = {"x": round(_TREND_WIDTH / 2, 1), "y": round(y_for(scores[0]), 1)}
        return {
            "has_data": True,
            "is_single_point": True,
            "points": points,
            "point_count": 1,
            "latest_score": scores[0],
            "marker": marker,
            "polyline": "",
            "area_path": "",
        }

    xs = [index * (_TREND_WIDTH / (count - 1)) for index in range(count)]
    ys = [y_for(score) for score in scores]
    coords = list(zip(xs, ys))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    baseline = _TREND_HEIGHT - _TREND_PAD_BOTTOM
    area_path = (
        f"M{coords[0][0]:.1f},{baseline:.1f} "
        + " ".join(f"L{x:.1f},{y:.1f}" for x, y in coords)
        + f" L{coords[-1][0]:.1f},{baseline:.1f} Z"
    )
    marker = {"x": round(coords[-1][0], 1), "y": round(coords[-1][1], 1)}

    return {
        "has_data": True,
        "is_single_point": False,
        "points": points,
        "point_count": count,
        "latest_score": scores[-1],
        "marker": marker,
        "polyline": polyline,
        "area_path": area_path,
    }
