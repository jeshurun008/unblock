from .scanners.base import Signal, Severity

SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.WARNING: 20,
    Severity.BLOCKING: 60,
}

BLOCKED_THRESHOLD = 50
STALE_THRESHOLD = 15


def score(signals: list[Signal]) -> int:
    return sum(SEVERITY_WEIGHT[s.severity] for s in signals)


def status(signals: list[Signal]) -> str:
    s = score(signals)
    if s >= BLOCKED_THRESHOLD:
        return "blocked"
    if s >= STALE_THRESHOLD:
        return "stale"
    return "ok"


def top_signal(signals: list[Signal]) -> Signal | None:
    """Highest severity signal, used as the one-line summary in `scan`."""
    if not signals:
        return None
    order = {Severity.BLOCKING: 2, Severity.WARNING: 1, Severity.INFO: 0}
    return max(signals, key=lambda s: order[s.severity])
