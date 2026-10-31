import re
from datetime import datetime, timedelta, timezone

from app.analysis import build_timeline, compute_regressions, rank_hypotheses

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
INCIDENT = {"id": "inc_x", "title": "t", "service": "support-agent",
            "environment": "production", "severity": "high",
            "created": NOW.isoformat()}


def span(minutes_before: float, duration_ms: float, status: str = "ok") -> dict:
    return {"created": (NOW - timedelta(minutes=minutes_before)).isoformat(),
            "duration_ms": duration_ms, "status": status}


def test_regression_reports_insufficient_data_instead_of_guessing():
    result = compute_regressions([span(10, 100)], INCIDENT["created"])
    assert result["insufficient_data"] is True
    assert result["latency_regressed"] is False and result["error_spike"] is False


def test_latency_regression_detected_against_baseline_window():
    baseline = [span(120 + i, 100.0) for i in range(10)]
    recent = [span(i + 1, 400.0) for i in range(10)]
    result = compute_regressions(baseline + recent, INCIDENT["created"])
    assert result["insufficient_data"] is False
    assert result["latency_regressed"] is True
    assert result["latency_ratio"] >= 1.5
    assert result["error_spike"] is False


def test_error_spike_detected():
    baseline = [span(120 + i, 100.0) for i in range(10)]
    recent = [span(i + 1, 100.0, "error" if i < 5 else "ok") for i in range(10)]
    result = compute_regressions(baseline + recent, INCIDENT["created"])
    assert result["error_spike"] is True
    assert result["latency_regressed"] is False


def test_hypotheses_rank_change_correlation_first_and_cite_sources():
    baseline = [span(120 + i, 100.0) for i in range(10)]
    recent = [span(i + 1, 400.0) for i in range(10)]
    regressions = compute_regressions(baseline + recent, INCIDENT["created"])
    git_events = [{"event": "deployment", "repository": "acme/rag",
                   "ref": "refs/heads/main", "after_sha": "a" * 40,
                   "environment": "production",
                   "created": (NOW - timedelta(minutes=30)).isoformat()}]
    ranked = rank_hypotheses(INCIDENT, regressions, git_events, [
        {"label": "Timeout", "evidence_id": "evd_1", "line": 3, "excerpt": "deadline exceeded"}])
    assert ranked[0]["generator"] == "change-correlation"
    assert ranked[0]["confidence"] >= 0.75
    assert all(h["evidence"] for h in ranked if h["status"] != "inconclusive")
    generators = {h["generator"] for h in ranked}
    assert {"latency-window", "evidence-signature"} <= generators


def test_hypotheses_inconclusive_when_nothing_clears_thresholds():
    regressions = compute_regressions([], INCIDENT["created"])
    ranked = rank_hypotheses(INCIDENT, regressions, [], [])
    assert len(ranked) == 1
    assert ranked[0]["status"] == "inconclusive"
    assert ranked[0]["confidence"] == 0.0


def test_timeline_is_chronological_and_source_linked():
    regressions = compute_regressions([], INCIDENT["created"])
    evidence = [{"id": "evd_1", "label": "api.log", "sha256": "f" * 64,
                 "created": (NOW - timedelta(minutes=5)).isoformat()}]
    git_events = [{"event": "push", "repository": "acme/rag", "ref": "refs/heads/main",
                   "after_sha": "b" * 40, "environment": None,
                   "created": (NOW - timedelta(minutes=90)).isoformat()}]
    timeline = build_timeline(INCIDENT, evidence, git_events, regressions)
    stamps = [entry["at"] for entry in timeline]
    assert stamps == sorted(stamps)
    assert [entry["kind"] for entry in timeline] == ["change", "evidence", "incident"]
    assert all(entry["source"]["type"] for entry in timeline)


def _create_incident(admin):
    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^"]+)"', form.text).group(1)
    created = admin.post("/app/incidents", data={
        "title": "Groundedness regression", "service": "support-agent",
        "environment": "production", "severity": "high", "token": token},
        follow_redirects=False)
    return created.headers["location"].rsplit("/", 1)[-1], token


def test_hypotheses_route_persists_and_api_returns_them(admin):
    incident_id, token = _create_incident(admin)
    generated = admin.post(f"/app/incidents/{incident_id}/hypotheses",
                           data={"token": token}, follow_redirects=False)
    assert generated.status_code == 303
    api = admin.get(f"/api/incidents/{incident_id}/hypotheses")
    assert api.status_code == 200
    body = api.json()
    assert body["hypotheses"], "at least the inconclusive hypothesis is stored"
    assert body["hypotheses"][0]["status"] in {"open", "inconclusive"}
    detail = admin.get(f"/app/incidents/{incident_id}")
    assert "Cause hypotheses" in detail.text
    assert "Window comparison" in detail.text


def test_hypotheses_api_requires_login(client):
    response = client.get("/api/incidents/inc_x/hypotheses")
    assert response.status_code in (302, 303, 401, 403)
