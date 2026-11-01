"""Deterministic paired replay checks for reviewed AI evaluation examples.

This module does not call a model or claim semantic quality. It compares model
outputs against expected labels using exact-match accuracy so teams can catch
obvious regressions before a release.
"""
from __future__ import annotations

import json
from dataclasses import dataclass


MAX_CASES = 1000
MAX_FIELD_CHARS = 8000


class ReplayInputError(ValueError):
    """Raised when an uploaded replay set is malformed or too large."""


@dataclass(frozen=True)
class ReplayResult:
    cases: int
    baseline_passes: int
    candidate_passes: int
    baseline_rate: float
    candidate_rate: float
    threshold: float
    gate: str
    source_sha256: str


def evaluate_jsonl(raw: bytes, threshold_percent: float, source_sha256: str) -> ReplayResult:
    """Score paired expected/baseline/candidate strings without storing payloads."""
    if not 0 <= threshold_percent <= 100:
        raise ReplayInputError("Threshold must be between 0 and 100 percent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayInputError("Replay file must be UTF-8 JSONL") from exc

    cases = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(cases) >= MAX_CASES:
            raise ReplayInputError(f"Replay sets are limited to {MAX_CASES} cases")
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayInputError(f"Line {line_number} is not valid JSON") from exc
        if not isinstance(item, dict):
            raise ReplayInputError(f"Line {line_number} must be a JSON object")
        for key in ("expected", "baseline", "candidate"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ReplayInputError(f"Line {line_number} needs non-empty string fields: expected, baseline, candidate")
            if len(value) > MAX_FIELD_CHARS:
                raise ReplayInputError(f"Line {line_number} contains a field longer than {MAX_FIELD_CHARS} characters")
        cases.append(item)
    if not cases:
        raise ReplayInputError("Replay file must contain at least one JSONL case")

    baseline = sum(item["baseline"].strip() == item["expected"].strip() for item in cases)
    candidate = sum(item["candidate"].strip() == item["expected"].strip() for item in cases)
    baseline_rate = baseline / len(cases) * 100
    candidate_rate = candidate / len(cases) * 100
    gate = "pass" if candidate_rate >= threshold_percent and candidate_rate >= baseline_rate else "hold"
    return ReplayResult(
        cases=len(cases), baseline_passes=baseline, candidate_passes=candidate,
        baseline_rate=round(baseline_rate, 1), candidate_rate=round(candidate_rate, 1),
        threshold=round(threshold_percent, 1), gate=gate, source_sha256=source_sha256,
    )


def dataset_version(cases: list[dict]) -> str:
    """Stable fingerprint of the active case set: any edit changes the version."""
    import hashlib
    digest = hashlib.sha256()
    for case in sorted(cases, key=lambda c: c["id"]):
        digest.update(json.dumps(
            {"id": case["id"], "expected": case["expected"], "baseline": case["baseline"],
             "label": case.get("label", "")}, sort_keys=True).encode())
    return digest.hexdigest()[:16]


def evaluate_candidates(raw: bytes, stored_cases: list[dict], threshold_percent: float,
                        source_sha256: str) -> ReplayResult:
    """Score a candidate-only JSONL against stored, reviewed eval cases.

    Each line must be {"case_id": ..., "candidate": ...}. Expected and baseline
    come from the reviewed case set, so the candidate author cannot redefine
    what passing means. Every active case must be answered exactly once.
    """
    if not 0 <= threshold_percent <= 100:
        raise ReplayInputError("Threshold must be between 0 and 100 percent")
    if not stored_cases:
        raise ReplayInputError("This incident has no active eval cases yet")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayInputError("Candidate file must be UTF-8 JSONL") from exc

    by_id = {case["id"]: case for case in stored_cases}
    answers: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(answers) >= MAX_CASES:
            raise ReplayInputError(f"Candidate sets are limited to {MAX_CASES} answers")
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayInputError(f"Line {line_number} is not valid JSON") from exc
        if not isinstance(item, dict):
            raise ReplayInputError(f"Line {line_number} must be a JSON object")
        case_id, candidate = item.get("case_id"), item.get("candidate")
        if not isinstance(case_id, str) or case_id not in by_id:
            raise ReplayInputError(f"Line {line_number}: unknown or missing case_id")
        if case_id in answers:
            raise ReplayInputError(f"Line {line_number}: duplicate answer for {case_id}")
        if not isinstance(candidate, str) or not candidate.strip():
            raise ReplayInputError(f"Line {line_number}: candidate must be a non-empty string")
        if len(candidate) > MAX_FIELD_CHARS:
            raise ReplayInputError(f"Line {line_number}: candidate longer than {MAX_FIELD_CHARS} characters")
        answers[case_id] = candidate
    missing = sorted(set(by_id) - set(answers))
    if missing:
        raise ReplayInputError(f"Missing candidate answers for {len(missing)} case(s), e.g. {missing[0]}")

    baseline = sum(case["baseline"].strip() == case["expected"].strip() for case in stored_cases)
    candidate = sum(answers[cid].strip() == by_id[cid]["expected"].strip() for cid in by_id)
    total = len(stored_cases)
    baseline_rate = baseline / total * 100
    candidate_rate = candidate / total * 100
    gate = "pass" if candidate_rate >= threshold_percent and candidate_rate >= baseline_rate else "hold"
    return ReplayResult(
        cases=total, baseline_passes=baseline, candidate_passes=candidate,
        baseline_rate=round(baseline_rate, 1), candidate_rate=round(candidate_rate, 1),
        threshold=round(threshold_percent, 1), gate=gate, source_sha256=source_sha256,
    )
