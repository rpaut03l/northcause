"""Signed, content-addressed replay proof records."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _private_key(data_dir: Path) -> Ed25519PrivateKey:
    configured = os.getenv("NORTHCAUSE_PROOF_PRIVATE_KEY", "").strip()
    if configured:
        raw = configured.replace("\\n", "\n").encode("utf-8")
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("NORTHCAUSE_PROOF_PRIVATE_KEY must be an Ed25519 PEM private key")
        return key
    if os.getenv("NORTHCAUSE_ENV", "development").lower() in {"production", "prod"}:
        raise RuntimeError("Set NORTHCAUSE_PROOF_PRIVATE_KEY in production to keep proof signatures verifiable")
    path = data_dir / "proof-signing-key.pem"
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Local proof signing key is not Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def ensure_signing_key(data_dir: Path) -> None:
    """Fail early before a replay is recorded if durable signing is unavailable."""
    _private_key(data_dir)


def sign_record(payload: dict, previous_hash: str, data_dir: Path) -> dict[str, str]:
    key = _private_key(data_dir)
    payload_bytes = canonical_json(payload)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    record_hash = hashlib.sha256((previous_hash + "." + payload_hash).encode("ascii")).hexdigest()
    signature = key.sign(bytes.fromhex(record_hash))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "payload": payload_bytes.decode("utf-8"),
        "payload_sha256": payload_hash,
        "previous_hash": previous_hash,
        "record_hash": record_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": base64.b64encode(public).decode("ascii"),
        "key_fingerprint": hashlib.sha256(public).hexdigest(),
    }


def verify_record(record: dict) -> bool:
    try:
        payload = json.loads(record["payload"])
        payload_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
        if payload_hash != record["payload_sha256"]:
            return False
        expected = hashlib.sha256((record["previous_hash"] + "." + payload_hash).encode("ascii")).hexdigest()
        if expected != record["record_hash"]:
            return False
        public = base64.b64decode(record["public_key"], validate=True)
        if hashlib.sha256(public).hexdigest() != record["key_fingerprint"]:
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(record["signature"], validate=True), bytes.fromhex(expected))
        return True
    except Exception:
        return False
