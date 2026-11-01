import io
import json
import re

import pytest

from app.replay import ReplayInputError, dataset_version, evaluate_candidates

CASES = [
    {"id": "case_a", "label": "cites policy", "expected": "Cites the refund policy", "baseline": "Cites the refund policy"},
    {"id": "case_b", "label": "limit answer", "expected": "Limit is 50", "baseline": "Limit is 40"},
]


def _jsonl(rows):
    return ("\n".join(json.dumps(r) for r in rows)).encode()


def test_dataset_version_changes_when_a_case_changes():
    v1 = dataset_version(CASES)
    changed = [dict(CASES[0]), {**CASES[1], "expected": "Limit is 60"}]
    assert v1 != dataset_version(changed)
    assert v1 == dataset_version(list(reversed(CASES)))  # order-independent


def test_candidates_scored_against_stored_expected_and_baseline():
    raw = _jsonl([{"case_id": "case_a", "candidate": "Cites the refund policy"},
                  {"case_id": "case_b", "candidate": "Limit is 50"}])
    result = evaluate_candidates(raw, CASES, 80, "f" * 64)
    assert result.cases == 2
    assert result.baseline_passes == 1 and result.candidate_passes == 2
    assert result.gate == "pass"


def test_candidate_regression_is_held():
    raw = _jsonl([{"case_id": "case_a", "candidate": "no citation"},
                  {"case_id": "case_b", "candidate": "Limit is 50"}])
    result = evaluate_candidates(raw, CASES, 40, "f" * 64)
    assert result.candidate_rate == 50.0
    assert result.gate == "pass"  # equals baseline and clears threshold
    # below threshold → hold
    assert evaluate_candidates(raw, CASES, 60, "f" * 64).gate == "hold"
    # regresses against baseline → hold even with threshold 0
    raw2 = _jsonl([{"case_id": "case_a", "candidate": "no citation"},
                   {"case_id": "case_b", "candidate": "wrong"}])
    assert evaluate_candidates(raw2, CASES, 0, "f" * 64).gate == "hold"


def test_candidates_must_cover_every_active_case():
    raw = _jsonl([{"case_id": "case_a", "candidate": "Cites the refund policy"}])
    with pytest.raises(ReplayInputError, match="Missing candidate answers"):
        evaluate_candidates(raw, CASES, 80, "f" * 64)


def test_unknown_case_id_and_duplicates_rejected():
    with pytest.raises(ReplayInputError, match="unknown or missing case_id"):
        evaluate_candidates(_jsonl([{"case_id": "nope", "candidate": "x"}]), CASES, 80, "f" * 64)
    raw = _jsonl([{"case_id": "case_a", "candidate": "x"}, {"case_id": "case_a", "candidate": "y"}])
    with pytest.raises(ReplayInputError, match="duplicate answer"):
        evaluate_candidates(raw, CASES, 80, "f" * 64)


def test_empty_case_set_is_an_error_not_a_pass():
    with pytest.raises(ReplayInputError, match="no active eval cases"):
        evaluate_candidates(b"{}", [], 80, "f" * 64)


def _create_incident(admin):
    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^"]+)"', form.text).group(1)
    created = admin.post("/app/incidents", data={
        "title": "Groundedness regression", "service": "support-agent",
        "environment": "production", "severity": "high", "token": token},
        follow_redirects=False)
    return created.headers["location"].rsplit("/", 1)[-1], token


def test_eval_case_lifecycle_and_stored_replay(admin):
    incident_id, token = _create_incident(admin)
    for label, expected, baseline in (("cites policy", "Cites the refund policy", "No citation"),
                                      ("limit answer", "Limit is 50", "Limit is 50")):
        created = admin.post(f"/app/incidents/{incident_id}/eval-cases",
                             data={"label": label, "expected": expected, "baseline": baseline,
                                   "token": token}, follow_redirects=False)
        assert created.status_code == 303
    api = admin.get(f"/api/incidents/{incident_id}/eval-cases").json()
    assert len(api["cases"]) == 2 and api["dataset_version"]
    answers = [{"case_id": case["id"], "candidate": case["expected"]} for case in api["cases"]]
    upload = io.BytesIO(("\n".join(json.dumps(a) for a in answers)).encode())
    ran = admin.post(f"/app/incidents/{incident_id}/replay",
                     data={"token": token, "threshold": "80", "mode": "stored"},
                     files={"file": ("candidates.jsonl", upload, "application/jsonl")},
                     follow_redirects=False)
    assert ran.status_code == 303
    detail = admin.get(f"/app/incidents/{incident_id}/replay")
    assert "Dataset version" in detail.text
    assert api["dataset_version"] in detail.text
    # retire one case → dataset version changes
    retire = admin.post(f"/app/eval-cases/{api['cases'][0]['id']}/retire",
                        data={"token": token}, follow_redirects=False)
    assert retire.status_code == 303
    api2 = admin.get(f"/api/incidents/{incident_id}/eval-cases").json()
    assert len(api2["cases"]) == 1
    assert api2["dataset_version"] != api["dataset_version"]


def test_eval_case_rejects_foreign_evidence_ref(admin):
    incident_id, token = _create_incident(admin)
    bad = admin.post(f"/app/incidents/{incident_id}/eval-cases",
                     data={"label": "x", "expected": "a", "baseline": "b",
                           "source_evidence_id": "evd_doesnotexist", "token": token},
                     follow_redirects=False)
    assert bad.status_code == 400
