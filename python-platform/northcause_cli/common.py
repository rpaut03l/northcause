from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

MAX_INPUT_BYTES = 2 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(r"(?i)(api[\s_-]?key|access[\s_-]?token|password|secret)(\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{12,}"),
)


def read_bounded(path: Path, maximum: int = MAX_INPUT_BYTES) -> bytes:
    data = path.read_bytes()
    if len(data) > maximum:
        raise ValueError(f"{path} exceeds the {maximum} byte input limit")
    return data


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def api_base(value: str) -> str:
    value = value.rstrip("/")
    parsed = urlparse(value)
    if not parsed.hostname or parsed.username or parsed.password or len(value) > 500:
        raise ValueError("Provide a valid API URL without embedded credentials")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise ValueError("API URL must use HTTPS, except for localhost development")
    return value


def request_json(url: str, *, payload: dict | None = None, token: str | None = None, timeout: float = 10) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("Server response exceeds 2 MiB")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach {url}: {exc.reason}") from exc


def default_api_url(cli_value: str | None) -> str:
    value = cli_value or os.getenv("NORTHCAUSE_API_URL", "http://127.0.0.1:8888")
    return api_base(value)
