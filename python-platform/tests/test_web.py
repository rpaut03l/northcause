def test_public_pages_render_with_site_navigation(client):
    for path in ("/", "/product", "/security", "/docs", "/pricing", "/contact", "/demo"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "Northcause" in response.text


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
