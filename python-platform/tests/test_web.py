def test_public_pages_render_with_site_navigation(client):
    for path in ("/", "/product", "/security", "/docs", "/pricing", "/contact", "/demo"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "NorthCause" in response.text


def test_homepage_contains_product_preview_and_primary_navigation(client):
    response = client.get("/")
    assert "Find the cause." in response.text
    assert "Verify the fix." in response.text
    assert "Illustrative interface" in response.text
    assert 'href="/pricing"' in response.text


def test_incidents_are_scoped_to_an_environment(admin):
    import re

    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^"]+)"', form.text).group(1)
    created = admin.post(
        "/app/incidents",
        data={
            "title": "RAG latency after index update",
            "service": "support-agent",
            "environment": "staging",
            "severity": "high",
            "token": token,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    detail = admin.get(created.headers["location"])
    assert detail.status_code == 200
    assert "staging" in detail.text


def test_incident_rejects_unknown_environment(admin):
    import re

    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^"]+)"', form.text).group(1)
    response = admin.post(
        "/app/incidents",
        data={
            "title": "Invalid environment",
            "service": "api",
            "environment": "production-everywhere",
            "severity": "medium",
            "token": token,
        },
    )
    assert response.status_code == 400


def test_remediation_draft_requires_and_records_human_review(admin):
    import re
    from app.main import db

    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^"]+)"', form.text).group(1)
    created = admin.post(
        "/app/incidents",
        data={"title": "Model latency regression", "environment": "production", "token": token},
        follow_redirects=False,
    )
    incident_path = created.headers["location"]
    detail = admin.get(incident_path)
    token = re.search(r'name="token" value="([^"]+)"', detail.text).group(1)
    drafted = admin.post(
        f"{incident_path}/draft",
        data={"body": "Compare the index configuration with the previous release.", "token": token},
        follow_redirects=False,
    )
    assert drafted.status_code == 303
    with db() as conn:
        draft_id = conn.execute("SELECT id FROM drafts ORDER BY created DESC LIMIT 1").fetchone()["id"]
    reviewed = admin.post(
        f"/app/drafts/{draft_id}/decision",
        data={"decision": "approved", "reason": "Reviewed against the deployment record.", "token": token},
        follow_redirects=False,
    )
    assert reviewed.status_code == 303
    page = admin.get(incident_path)
    assert "approved" in page.text
    assert "Reviewed against the deployment record." in page.text


def test_demo_is_read_only_and_uses_sample_records(client):
    response = client.get("/demo")
    assert response.status_code == 200
    assert "READ-ONLY PRODUCT TOUR" in response.text
    assert "fictional sample data" in response.text
    assert "DEMO-104" in response.text


def test_workspace_requires_authentication(client):
    response = client.get("/app", follow_redirects=False)
    assert response.status_code == 401


def test_login_and_workspace_are_available_to_admin(admin):
    response = admin.get("/app")
    assert response.status_code == 200
    assert "Workspace" in response.text


def test_contact_form_rejects_missing_csrf(client):
    response = client.post(
        "/contact",
        data={"name": "Rohit", "email": "rohit@example.com", "message": "Pilot"},
    )
    assert response.status_code == 403


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_otlp_ingest_requires_token_and_discards_prompt_attributes(client, monkeypatch):
    import json
    from app.main import db

    monkeypatch.setenv("NORTHCAUSE_OTEL_INGEST_TOKEN", "local-test-token")
    payload = {"resourceSpans": [{
        "resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "rag-api"}},
            {"key": "gen_ai.prompt", "value": {"stringValue": "must never persist"}},
        ]},
        "scopeSpans": [{"spans": [{
            "traceId": "a" * 32, "spanId": "b" * 16, "name": "chat completion",
            "startTimeUnixNano": "1000000", "endTimeUnixNano": "3000000",
            "attributes": [{"key": "gen_ai.request.model", "value": {"stringValue": "model-x"}},
                           {"key": "gen_ai.prompt", "value": {"stringValue": "private prompt"}}],
        }]}],
    }]}
    assert client.post("/api/otel/v1/traces", json=payload).status_code == 401
    accepted = client.post("/api/otel/v1/traces", json=payload, headers={"Authorization": "Bearer local-test-token"})
    assert accepted.status_code == 200
    assert accepted.json() == {"accepted_spans": 1, "duplicate_spans": 0}
    repeated = client.post("/api/otel/v1/traces", json=payload, headers={"Authorization": "Bearer local-test-token"})
    assert repeated.json() == {"accepted_spans": 0, "duplicate_spans": 1}
    with db() as conn:
        span = conn.execute("SELECT * FROM otel_spans").fetchone()
    assert span["service"] == "rag-api"
    assert span["name"] == "redacted-span"
    assert "prompt" not in span["attributes"]


def test_github_webhook_verifies_hmac_and_deduplicates(client, monkeypatch):
    import hashlib
    import hmac
    import json

    secret = "webhook-test-secret"
    monkeypatch.setenv("NORTHCAUSE_GITHUB_WEBHOOK_SECRET", secret)
    payload = json.dumps({"repository": {"full_name": "northcause/sample"}, "ref": "refs/heads/main",
                         "before": "1" * 40, "after": "2" * 40}).encode()
    signature = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    headers = {"X-GitHub-Event": "push", "X-GitHub-Delivery": "delivery-12345678", "X-Hub-Signature-256": signature}
    invalid = dict(headers, **{"X-Hub-Signature-256": "sha256=" + "0" * 64})
    assert client.post("/api/integrations/github/webhook", content=payload, headers=invalid).status_code == 401
    first = client.post("/api/integrations/github/webhook", content=payload, headers=headers)
    again = client.post("/api/integrations/github/webhook", content=payload, headers=headers)
    assert first.json()["accepted"] is True and first.json()["duplicate"] is False
    assert again.json()["duplicate"] is True


def test_semantic_evaluator_requires_login_and_stores_only_aggregate(admin, monkeypatch):
    import app.main as main

    monkeypatch.setattr(main, "score_cases", lambda cases: {"cases": len(cases), "passed": 1, "pass_rate": 100.0,
                                                             "mean_score": 0.91, "results": [{"score": 0.91, "pass": True, "reason": "Supported"}]})
    response = admin.post("/api/evaluations/semantic", json={"cases": [{"criteria": "Use source facts", "expected": "A blue whale is a mammal", "candidate": "A blue whale is a mammal"}]})
    assert response.status_code == 200
    assert response.json()["mean_score"] == 0.91
    assert "candidate" not in response.text


def test_sos_intake_creates_incident_and_discloses_unstaffed_status(admin):
    response = admin.post("/api/sos", json={"title": "Model is leaking secrets", "service": "support-rag",
                                             "environment": "production", "severity": "critical",
                                             "summary": "API key=secret-value is present in output"})
    assert response.status_code == 200
    assert response.json()["status"] == "received"
    assert response.json()["response_service"] == "not_staffed"
    from app.main import db
    with db() as conn:
        evidence = conn.execute("SELECT body FROM evidence WHERE incident_id=?", (response.json()["incident_id"],)).fetchone()
    assert "secret-value" not in evidence["body"]


def test_signed_proof_records_detect_tampering(tmp_path):
    from app.proofs import sign_record, verify_record

    signed = sign_record({"schema": "northcause.replay-proof.v1", "gate": "pass"}, "0" * 64, tmp_path)
    assert verify_record(signed)
    signed["payload"] = '{"schema":"forged","gate":"pass"}'
    assert not verify_record(signed)


def test_successful_replay_creates_downloadable_and_verifiable_proof(admin):
    import json
    import re
    from app.main import db

    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^\"]+)"', form.text).group(1)
    created = admin.post("/app/incidents", data={"title": "Evidence replay", "service": "rag", "token": token}, follow_redirects=False)
    incident_path = created.headers["location"]
    detail = admin.get(incident_path)
    token = re.search(r'name="token" value="([^\"]+)"', detail.text).group(1)
    rows = b'{"expected":"grounded answer","baseline":"grounded answer","candidate":"grounded answer"}\n'
    replay = admin.post(f"{incident_path}/replay", data={"threshold": "80", "token": token}, files={"file": ("cases.jsonl", rows, "application/x-ndjson")}, follow_redirects=False)
    assert replay.status_code == 303
    with db() as conn:
        proof = conn.execute("SELECT id FROM proof_records ORDER BY created DESC LIMIT 1").fetchone()
    assert proof
    report = admin.get(f"/api/proofs/{proof['id']}")
    assert report.status_code == 200
    assert report.json()["algorithm"] == "Ed25519"
    assert report.json()["payload"]["result"]["gate"] == "pass"
    assert admin.get(f"/api/proofs/{proof['id']}/verify").json()["valid"] is True


def test_evidence_linked_playbook_remains_a_draft(admin):
    import re
    from app.main import db

    form = admin.get("/app/incidents/new")
    token = re.search(r'name="token" value="([^\"]+)"', form.text).group(1)
    created = admin.post("/app/incidents", data={"title": "RAG timeout", "service": "search", "token": token}, follow_redirects=False)
    path = created.headers["location"]
    detail = admin.get(path)
    token = re.search(r'name="token" value="([^\"]+)"', detail.text).group(1)
    uploaded = admin.post(f"{path}/evidence", data={"label": "trace", "token": token}, files={"file": ("trace.log", b"retrieval failed: deadline exceeded", "text/plain")}, follow_redirects=False)
    assert uploaded.status_code == 303
    admin.post(f"{path}/investigate", data={"token": token}, follow_redirects=False)
    drafted = admin.post(f"{path}/recommend", data={"token": token}, follow_redirects=False)
    assert drafted.status_code == 303
    with db() as conn:
        row = conn.execute("SELECT body,status FROM drafts ORDER BY created DESC LIMIT 1").fetchone()
    assert row["status"] == "pending"
    assert "Evidence reference" in row["body"]
    assert "does not change" not in row["body"]


def test_public_pages_show_parent_company_and_single_hyphen_copy(client):
    for path in ("/", "/product", "/security", "/docs", "/pricing", "/contact", "/demo", "/login"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "Narmadya Innovations Pvt Ltd" in response.text, path
        assert 'href="https://narmadya.com/"' in response.text, path
        assert "A Narmadya Innovations Pvt Ltd company" not in response.text, path
        assert "--" not in response.text, path
