import base64
import html
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["DATA_DIR"] = "/tmp/abyss-panel-extended-test-import"
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
    with TestClient(panel.app) as c:
        yield c


def admin_login(client):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post("/login", data={
        "username": "admin", "password": "admin", "csrf_token": html.unescape(token)
    }, follow_redirects=False)
    assert response.status_code == 303
    return client.get("/api/overview").json()["csrf"]


def test_api_key_scopes_and_bot_client_lifecycle(client):
    csrf = admin_login(client)
    created = client.post("/api/admin/api-keys", json={
        "name": "test bot",
        "scopes": ["clients:read", "clients:write", "subscriptions:read"],
    }, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200, created.text
    token = created.json()["token"]
    assert token.startswith("aby_")
    assert token not in str(client.get("/api/admin/api-keys").json())

    auth = {"Authorization": "Bearer " + token}
    assert client.get("/api/v1/health", headers=auth).json()["ok"] is True
    denied = client.get("/api/v1/clients")
    assert denied.status_code == 401

    made = client.post("/api/v1/clients", json={
        "name": "API client", "duration_days": 14, "quota_gb": 3,
    }, headers=auth)
    assert made.status_code == 200, made.text
    item = made.json()
    assert item["subscription_url"].endswith("/sub/" + item["subscription_url"].rsplit("/", 1)[1])
    assert item["subscription_page_url"].startswith("https://")
    cid = item["id"]

    listing = client.get("/api/v1/clients", headers=auth)
    assert listing.status_code == 200
    assert any(x["id"] == cid for x in listing.json()["clients"])
    sub = client.get(f"/api/v1/clients/{cid}/subscription", headers=auth)
    assert sub.status_code == 200
    assert sub.json()["subscription_url"] == item["subscription_url"]

    paused = client.patch(f"/api/v1/clients/{cid}", json={"enabled": False}, headers=auth)
    assert paused.status_code == 200
    deleted = client.delete(f"/api/v1/clients/{cid}", headers=auth)
    assert deleted.status_code == 200

    key_id = created.json()["id"]
    revoked = client.delete(f"/api/admin/api-keys/{key_id}", headers={"X-CSRF-Token": csrf})
    assert revoked.status_code == 200
    assert client.get("/api/v1/clients", headers=auth).status_code == 401


def test_api_key_requires_scopes_and_rejects_invalid_payloads(client):
    csrf = admin_login(client)
    made = client.post("/api/admin/api-keys", json={
        "name": "read only", "scopes": ["clients:read"]
    }, headers={"X-CSRF-Token": csrf})
    assert made.status_code == 200
    auth = {"Authorization": "Bearer " + made.json()["token"]}
    assert client.get("/api/v1/clients", headers=auth).status_code == 200
    assert client.post("/api/v1/clients", json={"name": "blocked"}, headers=auth).status_code == 403
    invalid = client.post("/api/admin/api-keys", json={
        "name": "bad", "scopes": ["root:all"]
    }, headers={"X-CSRF-Token": csrf})
    assert invalid.status_code == 422


def test_system_metrics_is_admin_only_and_has_safe_shape(client):
    assert client.get("/api/system/metrics").status_code == 401
    admin_login(client)
    response = client.get("/api/system/metrics")
    assert response.status_code == 200, response.text
    data = response.json()
    assert "current" in data and "history" in data
    assert data["current"]["metrics_scope"] == "container"
    assert isinstance(data["current"]["clients_total"], int)
    assert "cpu_percent" in data["current"]
    assert "traffic_bytes_per_second" in data["current"]


def test_backup_download_and_restore_rejects_bad_files(client):
    csrf = admin_login(client)
    created = client.post("/api/clients", json={"name": "before backup"},
                          headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    backup = client.get("/api/backup")
    assert backup.status_code == 200
    assert "application/zip" in backup.headers["content-type"]
    assert "abysspanel-backup.zip" in backup.headers["content-disposition"]

    deleted = client.delete(f"/api/clients/{created.json()['id']}",
                            headers={"X-CSRF-Token": csrf})
    assert deleted.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0

    restored = client.post("/api/backup/restore",
        files={"backup": ("backup.zip", backup.content, "application/zip")},
        headers={"X-CSRF-Token": csrf})
    assert restored.status_code == 200, restored.text
    assert client.get("/api/overview").json()["total"] == 1

    invalid = client.post("/api/backup/restore",
        files={"backup": ("bad.zip", b"not a zip", "application/zip")},
        headers={"X-CSRF-Token": csrf})
    assert invalid.status_code == 400


def test_subscription_diagnostics_help_and_official_downloads(client):
    csrf = admin_login(client)
    created = client.post("/api/clients", json={"name": "diagnostic user"},
                          headers={"X-CSRF-Token": csrf})
    cid = created.json()["id"]
    info = client.get(f"/api/clients/{cid}/subscription").json()
    token = info["page_url"].rsplit("/", 1)[1]
    diag = client.get(f"/s/{token}/diagnostics")
    assert diag.status_code == 200, diag.text
    assert diag.json()["profile_count"] == 4
    help_page = client.get(f"/s/{token}/help")
    assert help_page.status_code == 200
    assert "v2rayNG" in help_page.text
    assert "https://github.com/2dust/v2rayNG/releases" in help_page.text
    page = client.get(info["page_url"].replace("https://testserver", "http://testserver"))
    assert page.status_code == 200
    assert "بررسی اتصال" in page.text
    assert "دانلود برنامه‌های رسمی" in page.text


def test_dashboard_injects_hamburger_api_backup_and_metrics(client):
    admin_login(client)
    page = client.get("/")
    assert page.status_code == 200
    assert 'id="abyssMenuButton"' in page.text
    assert 'id="apiPanel"' in page.text or "API و اتصال ربات" in page.text
    assert "پشتیبان‌گیری و بازیابی" in page.text
    assert "پایش زنده سرویس" in page.text
