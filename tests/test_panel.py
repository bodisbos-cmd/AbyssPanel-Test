import base64
import html
import os
import re
import sys
from pathlib import Path

# Ensure the repository root is importable regardless of pytest's import mode.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["DATA_DIR"] = "/tmp/abyss-panel-test-import"
os.environ["COOKIE_SECURE"] = "0"
os.environ["ABYSS_TEST_MODE"] = "1"

from fastapi.testclient import TestClient
import pytest

import app.main as panel


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(panel, "DATA_DIR", tmp_path)
    monkeypatch.setattr(panel, "DB_PATH", tmp_path / "panel.sqlite3")
    monkeypatch.setattr(panel, "XRAY_CONFIG", tmp_path / "xray.json")
    monkeypatch.setattr(panel, "xray_proc", None)

    async def fake_start_xray():
        panel.XRAY_CONFIG.write_text('{"test": true}', encoding="utf-8")

    monkeypatch.setattr(panel, "start_xray", fake_start_xray)
    with TestClient(panel.app) as test_client:
        yield test_client


def admin_client(client):
    page = client.get("/login")
    assert page.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    overview = client.get("/api/overview")
    assert overview.status_code == 200
    return overview.json()["csrf"]


def test_dashboard_requires_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/api/overview").status_code == 401


def test_create_pause_subscription_and_revoke(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}

    created = client.post("/api/clients", json={"name": "Test client"}, headers=headers)
    assert created.status_code == 200, created.text
    client_id = created.json()["id"]

    overview = client.get("/api/overview").json()
    assert overview["total"] == 1
    assert overview["active"] == 1

    link = client.get(f"/api/clients/{client_id}/subscription")
    assert link.status_code == 200
    assert link.json()["url"].startswith("https://")

    subscription = client.get(link.json()["url"].replace("https://testserver", "http://testserver"))
    assert subscription.status_code == 200
    configs = base64.b64decode(subscription.text).decode().splitlines()
    assert len(configs) == 3
    assert all(line.startswith("vless://") for line in configs)
    assert any("type=ws" in line for line in configs)
    assert any("type=httpupgrade" in line for line in configs)
    assert any("type=xhttp" in line for line in configs)

    paused = client.patch(f"/api/clients/{client_id}", json={"enabled": False}, headers=headers)
    assert paused.status_code == 200
    assert client.get(f"/sub/{_token_from_url(link.json()['url'])}").status_code == 404

    enabled = client.patch(f"/api/clients/{client_id}", json={"enabled": True}, headers=headers)
    assert enabled.status_code == 200

    revoked = client.delete(f"/api/clients/{client_id}", headers=headers)
    assert revoked.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0


def _token_from_url(url):
    return url.rsplit("/sub/", 1)[1]


def test_mutations_reject_missing_csrf(client):
    admin_client(client)
    response = client.post("/api/clients", json={"name": "Should fail"})
    assert response.status_code == 403


def test_failed_xray_update_rolls_back_new_client(client, monkeypatch):
    csrf = admin_client(client)
    calls = {"count": 0}

    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")

    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)
    response = client.post(
        "/api/clients",
        json={"name": "Rollback test"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert client.get("/api/overview").json()["total"] == 0
    assert calls["count"] == 2


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
