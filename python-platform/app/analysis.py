"""Deterministic regression signals, evidence timeline, and ranked cause hypotheses.

Everything in this module is rule-based and inspectable. No model calls, no
network access. Outputs are hypotheses for human review, never verified causal
findings, and an explicit "inconclusive" outcome is a first-class result.
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timedelta, timezone

RECENT_WINDOW_HOURS = 1.0       # window around incident start treated as "recent"
BASELINE_WINDOW_HOURS = 24.0    # lookback for baseline spans before the recent window
LATENCY_REGRESSION_RATIO = 1.5  # recent p95 must exceed baseline p95 by this factor
ERROR_RATE_DELTA = 0.10         # recent error rate must exceed baseline by this margin
MIN_RECENT_SPANS = 5
MIN_BASELINE_SPANS = 5
CHANGE_CORRELATION_HOURS = 2.0  # git change within this window before incident start


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(ts)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(0.95 * (len(ordered) - 1))))
    return float(ordered[index])


def compute_regressions(traces: list[dict], incident_created: str) -> dict:
    """Compare a recent window around incident start against a prior baseline.

    ``traces`` are matched-span dicts (same service/environment as the
    incident) with ``created`` ISO timestamps, ``duration_ms`` and ``status``.
    Returns latency and error-rate comparisons with an explicit
    ``insufficient_data`` flag — a missing baseline is reported, not guessed.
    """
    start = _parse(incident_created) or datetime.now(timezone.utc)
    recent_from = start - timedelta(hours=RECENT_WINDOW_HOURS)
    baseline_from = recent_from - timedelta(hours=BASELINE_WINDOW_HOURS)
    recent: list[dict] = []
    baseline: list[dict] = []
    for span in traces:
        created = _parse(span.get("created"))
        if created is None:
            continue
        if created >= recent_from:
            recent.append(span)
        elif created >= baseline_from:
            baseline.append(span)

    def summary(spans: list[dict]) -> dict:
        durations = [float(s.get("duration_ms") or 0) for s in spans]
        errors = sum(1 for s in spans if s.get("status") == "error")
        return {
            "span_count": len(spans),
            "error_count": errors,
            "error_rate": round(errors / len(spans), 4) if spans else 0.0,
            "p95_ms": round(_p95(durations), 2),
            "median_ms": round(statistics.median(durations), 2) if durations else 0.0,
        }

    recent_summary, baseline_summary = summary(recent), summary(baseline)
    sufficient = (recent_summary["span_count"] >= MIN_RECENT_SPANS
                  and baseline_summary["span_count"] >= MIN_BASELINE_SPANS)
    latency_regressed = bool(
        sufficient and baseline_summary["p95_ms"] > 0
        and recent_summary["p95_ms"] >= LATENCY_REGRESSION_RATIO * baseline_summary["p95_ms"])
    error_spike = bool(
        sufficient and recent_summary["error_count"] >= 3
        and recent_summary["error_rate"] >= baseline_summary["error_rate"] + ERROR_RATE_DELTA)
    return {
        "recent_window_start": recent_from.isoformat(),
        "baseline_window_start": baseline_from.isoformat(),
        "recent": recent_summary,
        "baseline": baseline_summary,
        "insufficient_data": not sufficient,
        "latency_regressed": latency_regressed,
        "latency_ratio": (round(recent_summary["p95_ms"] / baseline_summary["p95_ms"], 2)
                          if baseline_summary["p95_ms"] else None),
        "error_spike": error_spike,
        "note": "Deterministic window comparison of retained span metadata. Not a causal verdict.",
    }


def build_timeline(incident, evidence_rows, git_events: list[dict], regressions: dict) -> list[dict]:
    """One chronological, source-linked timeline: change events, evidence, windows."""
    entries: list[dict] = []
    for event in git_events:
        ref = event.get("after_sha") or event.get("ref") or ""
        entries.append({
            "at": event.get("created"), "kind": "change",
            "label": f"GitHub {event.get('event')} on {event.get('repository')}",
            "detail": (f"{event.get('ref') or ''} {str(ref)[:12]}".strip()
                       + (f" → {event.get('environment')}" if event.get("environment") else "")),
            "source": {"type": "github_delivery", "reference": str(ref)[:40]},
        })
    for row in evidence_rows:
        entries.append({
            "at": row["created"], "kind": "evidence",
            "label": f"Evidence uploaded: {row['label']}",
            "detail": f"sha256 {row['sha256'][:12]}…",
            "source": {"type": "evidence", "reference": row["id"]},
        })
    entries.append({
        "at": incident["created"], "kind": "incident",
        "label": f"Incident opened ({incident['severity']})",
        "detail": f"{incident['service']} / {incident['environment']}",
        "source": {"type": "incident", "reference": incident["id"]},
    })
    if not regressions.get("insufficient_data"):
        entries.append({
            "at": regressions["recent_window_start"], "kind": "window",
            "label": "Recent comparison window begins",
            "detail": (f"p95 {regressions['recent']['p95_ms']} ms vs baseline "
                       f"{regressions['baseline']['p95_ms']} ms; error rate "
                       f"{regressions['recent']['error_rate']} vs {regressions['baseline']['error_rate']}"),
            "source": {"type": "regression_windows", "reference": incident["id"]},
        })
    entries = [e for e in entries if _parse(e["at"]) is not None]
    entries.sort(key=lambda e: _parse(e["at"]))
    return entries[:200]


def _band(score: float) -> str:
    return "high" if score >= 0.75 else "medium" if score >= 0.45 else "low"


def rank_hypotheses(incident, regressions: dict, git_events: list[dict],
                    investigation_claims: list[dict]) -> list[dict]:
    """Rank cause hypotheses with explicit evidence refs and counterevidence.

    Scores are fixed heuristics so the same inputs always rank the same way.
    When nothing clears the bar, the single returned hypothesis is the
    inconclusive outcome — absence of a finding is reported, never papered over.
    """
    incident_start = _parse(incident["created"]) or datetime.now(timezone.utc)
    hypotheses: list[dict] = []

    recent_changes = []
    for event in git_events:
        created = _parse(event.get("created"))
        if created and timedelta(0) <= incident_start - created <= timedelta(hours=CHANGE_CORRELATION_HOURS):
            recent_changes.append(event)
    if recent_changes:
        score = 0.5
        counter: list[str] = []
        if regressions.get("latency_regressed") or regressions.get("error_spike"):
            score += 0.35
        else:
            counter.append("No latency or error regression detected in the matched spans after the change.")
        if regressions.get("insufficient_data"):
            counter.append("Span volume below minimum for a reliable window comparison.")
        newest = max(recent_changes, key=lambda e: e.get("created") or "")
        hypotheses.append({
            "statement": (f"A recent {newest.get('event')} to {newest.get('repository')} "
                          f"({str(newest.get('after_sha') or newest.get('ref') or '')[:12]}) "
                          "precedes the incident and may have introduced the failure."),
            "confidence": round(min(score, 0.95), 2),
            "evidence": [{"type": "github_delivery", "reference": str(e.get("after_sha") or e.get("ref") or "")[:40],
                          "at": e.get("created")} for e in recent_changes[:5]],
            "counterevidence": counter, "status": "open", "generator": "change-correlation",
        })

    if regressions.get("latency_regressed"):
        hypotheses.append({
            "statement": (f"p95 latency regressed {regressions['latency_ratio']}× "
                          f"({regressions['baseline']['p95_ms']} ms → {regressions['recent']['p95_ms']} ms) "
                          "in the recent window for this service and environment."),
            "confidence": round(min(0.45 + 0.1 * min(float(regressions["latency_ratio"] or 0), 3.0), 0.9), 2),
            "evidence": [{"type": "regression_windows", "reference": "latency",
                          "at": regressions["recent_window_start"]}],
            "counterevidence": ([] if regressions["recent"]["span_count"] >= 20
                                else ["Recent window has few spans; the p95 estimate is noisy."]),
            "status": "open", "generator": "latency-window",
        })

    if regressions.get("error_spike"):
        hypotheses.append({
            "statement": (f"Error rate rose from {regressions['baseline']['error_rate']} to "
                          f"{regressions['recent']['error_rate']} "
                          f"({regressions['recent']['error_count']} errors) in the recent window."),
            "confidence": round(min(0.5 + regressions["recent"]["error_rate"], 0.9), 2),
            "evidence": [{"type": "regression_windows", "reference": "error-rate",
                          "at": regressions["recent_window_start"]}],
            "counterevidence": [], "status": "open", "generator": "error-window",
        })

    by_label: dict[str, list[dict]] = {}
    for claim in investigation_claims:
        by_label.setdefault(claim.get("label", "finding"), []).append(claim)
    for label, claims in sorted(by_label.items()):
        hypotheses.append({
            "statement": f"Evidence contains {len(claims)} line(s) matching the '{label}' signature.",
            "confidence": round(min(0.35 + 0.05 * len(claims), 0.7), 2),
            "evidence": [{"type": "evidence_line", "reference": c.get("evidence_id", ""),
                          "line": c.get("line"), "excerpt": str(c.get("excerpt", ""))[:200]}
                         for c in claims[:5]],
            "counterevidence": ["Signature matches show symptoms in uploaded text; they do not establish cause."],
            "status": "open", "generator": "evidence-signature",
        })

    hypotheses.sort(key=lambda h: (-h["confidence"], h["generator"], h["statement"]))
    if not hypotheses:
        hypotheses = [{
            "statement": ("Inconclusive: no correlated change, span regression, or evidence "
                          "signature met the reporting thresholds."),
            "confidence": 0.0, "evidence": [],
            "counterevidence": ["Add evidence uploads, OTLP spans, or GitHub webhook events to widen the search."],
            "status": "inconclusive", "generator": "inconclusive",
        }]
    return hypotheses[:10]


def serialize_hypothesis(hypothesis: dict) -> tuple[str, str]:
    return json.dumps(hypothesis["evidence"]), json.dumps(hypothesis["counterevidence"])
