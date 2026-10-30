import os
import tempfile
import uuid

# Keep test state outside the repository and set paths before importing the app.
_test_data = tempfile.mkdtemp(prefix="northcause-tests-")
os.environ["NORTHCAUSE_DATA"] = _test_data
os.environ["NORTHCAUSE_DB"] = os.path.join(_test_data, "test.sqlite3")
os.environ["NORTHCAUSE_EVIDENCE"] = os.path.join(_test_data, "evidence")

import pytest
from fastapi.testclient import TestClient

from app.main import app, db, hash_pw, now, uid


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin(client):
    email = f"admin-{uuid.uuid4().hex}@example.com"
    with db() as conn:
        conn.execute(
            "INSERT INTO users VALUES(?,?,?,?,?,?)",
            (uid("usr"), email, hash_pw("correct horse battery"),
             "admin", "test-csrf-token", now()),
        )
    response = client.get("/login")
    token = response.cookies.get("nc_login_csrf")
    response = client.post(
        "/login",
        data={"email": email, "password": "correct horse battery",
              "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return client
