from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from app.proofs import verify_record
from app.replay import ReplayInputError, evaluate_jsonl
from .common import default_api_url, read_bounded, request_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="northcause", description="Local-first deterministic tools for NorthCause investigations.")
    parser.add_argument("--version", action="version", version="NorthCause CLI 0.1.0")
    sub = parser.add_subparsers(dest="group", required=True)

    doctor = sub.add_parser("doctor", help="Check the NorthCause API health endpoint")
    doctor.add_argument("--api-url", help="NorthCause API origin; defaults to NORTHCAUSE_API_URL or localhost:8888")

    incident = sub.add_parser("incident", help="Create and inspect a local incident packet")
    incident_sub = incident.add_subparsers(dest="action", required=True)
    create = incident_sub.add_parser("init", help="Create a local incident.json manifest")
    create.add_argument("--title", required=True)
    create.add_argument("--service", required=True)
    create.add_argument("--environment", choices=("development", "staging", "production"), default="production")
    create.add_argument("--out", type=Path, default=Path("incident.json"))
    attach = incident_sub.add_parser("add-evidence", help="Fingerprint and attach a local evidence file")
    attach.add_argument("manifest", type=Path)
    attach.add_argument("file", type=Path)
    inspect = incident_sub.add_parser("show", help="Print a local incident packet with evidence hashes")
    inspect.add_argument("manifest", type=Path)

    evidence = sub.add_parser("evidence", help="Inspect evidence without uploading it")
    evidence_sub = evidence.add_subparsers(dest="action", required=True)
    fingerprint = evidence_sub.add_parser("hash", help="Print a SHA-256 fingerprint")
    fingerprint.add_argument("file", type=Path)

    replay = sub.add_parser("replay", help="Run a deterministic paired exact-match check")
    replay_sub = replay.add_subparsers(dest="action", required=True)
    run = replay_sub.add_parser("run", help="Score expected/baseline/candidate JSONL records")
    run.add_argument("file", type=Path)
    run.add_argument("--threshold", type=float, default=90.0, help="Minimum candidate exact-match rate, 0-100 (default 90)")

    otel = sub.add_parser("otel", help="Send a bounded OTLP JSON batch to a configured NorthCause endpoint")
    otel_sub = otel.add_subparsers(dest="action", required=True)
    send = otel_sub.add_parser("send", help="POST OTLP JSON; prompt/completion content is filtered server-side")
    send.add_argument("file", type=Path)
    send.add_argument("--api-url", help="NorthCause API origin")

    proof = sub.add_parser("proof", help="Verify signed proof records")
    proof_sub = proof.add_subparsers(dest="action", required=True)
    verify = proof_sub.add_parser("verify", help="Verify a downloaded proof JSON file locally")
    verify.add_argument("file", type=Path)

    return parser


def _write_packet(args: argparse.Namespace) -> None:
    if not args.title.strip() or not args.service.strip() or len(args.title) > 180 or len(args.service) > 120:
        raise ValueError("Title and service must be non-empty; limits are 180 and 120 characters")
    packet = {
        "schema_version": "northcause.incident.v1",
        "title": args.title.strip(), "service": args.service.strip(),
        "environment": args.environment, "evidence": [],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    print(f"Created local incident packet: {args.out}")


def _attach(args: argparse.Namespace) -> None:
    packet = json.loads(args.manifest.read_text(encoding="utf-8"))
    if packet.get("schema_version") != "northcause.incident.v1" or not isinstance(packet.get("evidence"), list):
        raise ValueError("Unsupported incident manifest; expected northcause.incident.v1")
    content = read_bounded(args.file)
    packet["evidence"].append({
        "name": args.file.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
        "local_path": args.file.name,
    })
    args.manifest.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
    print(f"Attached fingerprint for {args.file.name}; evidence content remains local.")


def run(args: argparse.Namespace) -> int:
    if args.group == "doctor":
        base = default_api_url(args.api_url)
        result = request_json(base + "/healthz")
        print(json.dumps({"api_url": base, "health": result}, indent=2))
    elif args.group == "incident" and args.action == "init":
        _write_packet(args)
    elif args.group == "incident" and args.action == "add-evidence":
        _attach(args)
    elif args.group == "incident" and args.action == "show":
        print(json.dumps(json.loads(args.manifest.read_text(encoding="utf-8")), indent=2))
    elif args.group == "evidence":
        content = read_bounded(args.file)
        print(json.dumps({"file": args.file.name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}, indent=2))
    elif args.group == "replay":
        raw = read_bounded(args.file)
        result = evaluate_jsonl(raw, args.threshold, hashlib.sha256(raw).hexdigest())
        print(json.dumps(result.__dict__, indent=2))
        return 0 if result.gate == "pass" else 2
    elif args.group == "otel":
        token = os.getenv("NORTHCAUSE_OTEL_INGEST_TOKEN", "").strip()
        if not token:
            raise ValueError("Set NORTHCAUSE_OTEL_INGEST_TOKEN in your shell; NorthCause CLI never saves this token in config")
        raw = read_bounded(args.file)
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("resourceSpans"), list):
            raise ValueError("Expected OTLP JSON with a resourceSpans list")
        base = default_api_url(args.api_url)
        result = request_json(base + "/api/otel/v1/traces", payload=payload, token=token)
        print(json.dumps(result, indent=2))
    elif args.group == "proof":
        record = json.loads(args.file.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("Proof record must be a JSON object")
        valid = verify_record(record)
        print(json.dumps({"valid": valid, "record_hash": record.get("record_hash"), "key_fingerprint": record.get("key_fingerprint")}, indent=2))
        return 0 if valid else 2
    return 0


def main() -> None:
    try:
        code = run(_parser().parse_args())
    except (OSError, UnicodeError, json.JSONDecodeError, ReplayInputError, ValueError, RuntimeError) as exc:
        print(f"northcause: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
