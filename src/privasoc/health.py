"""Host health (D47), computed from what privasoc already receives: no agent on the device."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from privasoc.store import parse_ts

DEFAULTS = {
    "silence_min_minutes": 10,  # never alert on silence before this
    "silence_factor": 5,  # ... nor before 5 x the usual gap between lines
    "volume_drop": 0.2,  # recent rate below 20 % of the 24 h baseline
    "volume_spike": 5.0,  # recent rate above 5 x the baseline
    "parse_warning": 0.9,  # share of lines parsed (format drift)
    "parse_critical": 0.5,
    "skew_warning_s": 300,  # |received - @timestamp|
}
LEVEL = {"ok": 0, "warning": 1, "critical": 2}


def _minute(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M")


def compute(store, host: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    th = {**DEFAULTS, **(host.get("thresholds") or {})}
    status, reasons = "ok", []

    def flag(level: str, reason: str) -> None:
        nonlocal status
        reasons.append(reason)
        if LEVEL[level] > LEVEL[status]:
            status = level

    rows = store.stats(host["source"], _minute(now - timedelta(hours=24)))
    total_24h = sum(r[1] for r in rows)
    active_minutes = max(1, len(rows))
    # Baseline over the observed window (a host seen for 2 h has a 2 h baseline, not 24 h).
    span = 24 * 60
    if rows:
        first = datetime.strptime(rows[0][0], "%Y-%m-%dT%H:%M").replace(tzinfo=UTC)
        span = max(15.0, min(24 * 60, (now - first).total_seconds() / 60))
    per_minute = total_24h / span
    metrics = {"lines_24h": total_24h, "lines_per_min_24h": round(per_minute, 3)}

    last = parse_ts(host["last_seen"])
    silent_min = (now - last).total_seconds() / 60
    usual_gap = span / total_24h if total_24h else None
    limit = max(th["silence_min_minutes"], th["silence_factor"] * (usual_gap or 0))
    metrics["silent_minutes"] = round(silent_min, 1)
    if total_24h and silent_min > limit:
        flag("critical", f"silent for {silent_min:.0f} min (usual gap {usual_gap:.1f} min)")

    recent = [r for r in rows if r[0] >= _minute(now - timedelta(minutes=15))]
    recent_rate = sum(r[1] for r in recent) / 15
    metrics["lines_per_min_15m"] = round(recent_rate, 3)
    if per_minute and active_minutes >= 60:  # a baseline needs some history
        # a host with no line at all is the silence check's business, not a volume drop
        if 0 < recent_rate < th["volume_drop"] * per_minute:
            flag("warning", f"volume drop: {recent_rate:.2f}/min vs {per_minute:.2f}/min usual")
        if recent_rate > th["volume_spike"] * per_minute:
            flag("warning", f"volume spike: {recent_rate:.2f}/min vs {per_minute:.2f}/min usual")

    hour = [r for r in rows if r[0] >= _minute(now - timedelta(hours=1))]
    total_h, parsed_h = sum(r[1] for r in hour), sum(r[2] for r in hour)
    if total_h and host.get("format") and host["format"] != "unknown":
        rate = parsed_h / total_h
        metrics["parse_rate_1h"] = round(rate, 3)
        if rate < th["parse_critical"]:
            flag("critical", f"parse rate {rate:.0%}: format changed? propose a parser update")
        elif rate < th["parse_warning"]:
            flag("warning", f"parse rate {rate:.0%}: some lines go to quarantine")
    elif total_h and host.get("status") == "approved":
        flag("warning", "no parser yet: lines go to quarantine")

    skew_n = sum(r[4] for r in hour)
    if skew_n:
        skew = sum(r[3] for r in hour) / skew_n
        metrics["clock_skew_s"] = round(skew, 1)
        if skew > th["skew_warning_s"]:
            flag("warning", f"clock skew {skew:.0f} s between event time and reception")
    return {"source": host["source"], "status": status, "reasons": reasons, "metrics": metrics}
