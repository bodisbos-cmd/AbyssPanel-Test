import base64
import html
import os
import re
import sys
import http.client
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
        "scopes": ["clients:read", "clients:write", "subscriptions:read", "metrics:read"],
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

    # Renewal and quota changes are available to the sales bot without replacing the client UUID.
    renewed = client.patch(f"/api/v1/clients/{cid}",
        json={"duration_days": 30, "quota_gb": 7}, headers=auth)
    assert renewed.status_code == 200, renewed.text
    current = next(x for x in client.get("/api/v1/clients", headers=auth).json()["clients"] if x["id"] == cid)
    assert current["quota_bytes"] == 7 * 1024**3
    with panel.db() as c:
        c.execute("UPDATE clients SET used_bytes=12345 WHERE id=?", (cid,))
    reset = client.post(f"/api/v1/clients/{cid}/reset-usage", headers=auth)
    assert reset.status_code == 200, reset.text
    assert next(x for x in client.get("/api/v1/clients", headers=auth).json()["clients"] if x["id"] == cid)["used_bytes"] == 0
    metrics = client.get("/api/v1/system/metrics", headers=auth)
    assert metrics.status_code == 200 and "traffic_bytes_per_second" in metrics.json()["current"]

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
    no_csrf = client.post("/api/admin/api-keys", json={"name": "no csrf", "scopes": ["clients:read"]})
    assert no_csrf.status_code == 403
    made = client.post("/api/admin/api-keys", json={
        "name": "read only", "scopes": ["clients:read"]
    }, headers={"X-CSRF-Token": csrf})
    assert made.status_code == 200
    auth = {"Authorization": "Bearer " + made.json()["token"]}
    assert client.get("/api/v1/clients", headers=auth).status_code == 200
    assert client.get("/api/v1/system/metrics", headers=auth).status_code == 403
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
    assert diag.json()["profile_count"] == 6
    help_page = client.get(f"/s/{token}/help")
    assert help_page.status_code == 200
    assert "v2rayNG" in help_page.text
    assert "https://github.com/2dust/v2rayNG/releases" in help_page.text
    page = client.get(info["page_url"].replace("https://testserver", "http://testserver"))
    assert page.status_code == 200
    assert "بررسی اتصال" in page.text
    assert "دانلود برنامه‌های رسمی" in page.text
    assert "xhttp-stream-up" in page.text and "xhttp-stream-one" in page.text
    assert 'id="carrierSelect"' in page.text
    assert 'data-profile-choice="ws"' in page.text
    assert 'data-mark="ok"' in page.text and 'data-mark="fail"' in page.text
    assert "abyss-profile-results:" in page.text
    assert "نتیجه فقط روی همین دستگاه ذخیره می‌شود" in page.text


def test_dashboard_injects_hamburger_api_backup_and_metrics(client):
    admin_login(client)
    page = client.get("/")
    assert page.status_code == 200
    assert 'id="abyssMenuButton"' in page.text
    assert 'id="apiPanel"' in page.text or "API و اتصال ربات" in page.text
    assert "پشتیبان‌گیری و بازیابی" in page.text
    assert "پایش زنده سرویس" in page.text
    assert 'id="gCpu"' in page.text and 'id="gRam"' in page.text
    assert 'id="gDisk"' in page.text and 'id="gSpeed"' in page.text
    assert 'id="abyssMenuButton"' in page.text and 'aria-expanded="false"' in page.text


def test_subscription_html_escapes_names_and_shows_friendly_disabled_state(client):
    csrf = admin_login(client)
    created = client.post("/api/clients", json={"name": '<img src=x onerror="alert(1)">'}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    cid = created.json()["id"]
    info = client.get(f"/api/clients/{cid}/subscription").json()
    page = client.get(info["page_url"].replace("https://testserver", "http://testserver"))
    assert page.status_code == 200
    assert "&lt;img" in page.text
    assert '<img src=x onerror="alert(1)">' not in page.text

    paused = client.patch(f"/api/clients/{cid}", json={"enabled": False}, headers={"X-CSRF-Token": csrf})
    assert paused.status_code == 200
    unavailable = client.get(info["page_url"].replace("https://testserver", "http://testserver"))
    assert unavailable.status_code == 404
    assert "اشتراک در دسترس نیست" in unavailable.text


def _login_as(client, username, password):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post("/login", data={
        "username": username, "password": password, "csrf_token": html.unescape(token)
    }, follow_redirects=False)
    assert response.status_code == 303
    return client.get("/api/overview").json()["csrf"]


def test_multi_admin_roles_and_owner_only_controls(client):
    owner_csrf = admin_login(client)
    made = client.post("/api/admin/users", json={
        "username": "readonly", "password": "StrongPass123456", "role": "admin"
    }, headers={"X-CSRF-Token": owner_csrf})
    assert made.status_code == 200, made.text
    user_id = made.json()["id"]
    assert client.get("/api/admin/users").status_code == 200

    client.get("/logout")
    admin_csrf = _login_as(client, "readonly", "StrongPass123456")
    assert client.get("/api/overview").json()["user"]["role"] == "admin"
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/api-keys").status_code == 403
    made_client = client.post("/api/clients", json={"name": "managed by admin"},
                              headers={"X-CSRF-Token": admin_csrf})
    assert made_client.status_code == 200, made_client.text

    client.get("/logout")
    owner_csrf = _login_as(client, "admin", "admin")
    changed = client.patch(f"/api/admin/users/{user_id}", json={"role": "viewer"},
                           headers={"X-CSRF-Token": owner_csrf})
    assert changed.status_code == 200, changed.text

    client.get("/logout")
    viewer_csrf = _login_as(client, "readonly", "StrongPass123456")
    assert client.get("/api/overview").json()["user"]["role"] == "viewer"
    assert client.get("/api/admin/users").status_code == 403
    assert client.get("/api/admin/api-keys").status_code == 403
    cid = client.get("/api/overview").json()["clients"][0]["id"]
    denied = client.patch(f"/api/clients/{cid}", json={"enabled": False},
                          headers={"X-CSRF-Token": viewer_csrf})
    assert denied.status_code == 403


def test_profile_route_diagnostics_is_not_misrepresented_as_vpn_ping(client, monkeypatch):
    csrf = admin_login(client)

    class FakeResponse:
        status = 404
        def read(self, size=-1): return b""

    class FakeConnection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return FakeResponse()
        def close(self): pass

    monkeypatch.setattr(http.client, "HTTPConnection", FakeConnection)
    response = client.get("/api/system/profiles/check")
    assert response.status_code == 200, response.text
    data = response.json()
    assert len(data["checks"]) == 6
    assert all(item["route_ok"] for item in data["checks"])
    assert "پینگ واقعی تونل" in data["note"]

    made = client.post("/api/clients", json={"name": "route diagnostic"},
                       headers={"X-CSRF-Token": csrf})
    token = client.get(f"/api/clients/{made.json()['id']}/subscription").json()["page_url"].rsplit("/", 1)[1]
    customer_diag = client.get(f"/s/{token}/diagnostics")
    assert customer_diag.status_code == 200, customer_diag.text
    assert len(customer_diag.json()["route_checks"]) == 6
    assert all(item["http_status"] == 404 for item in customer_diag.json()["route_checks"])
    assert "cannot prove" in customer_diag.json()["note"]


def test_interactive_api_docs_require_an_admin_session(client):
    assert client.get("/api-docs").status_code == 401
    assert client.get("/api-docs/openapi.json").status_code == 401
    admin_login(client)
    page = client.get("/api-docs")
    assert page.status_code == 200
    assert "/api-docs/openapi.json" in page.text
    schema = client.get("/api-docs/openapi.json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert "/api/v1/clients" in paths
    assert "/api/v1/clients/{client_id}/reset-usage" in paths
    assert "/api/v1/system/metrics" in paths


def test_api_tokens_can_expire_and_are_revoked_on_use(client):
    csrf = admin_login(client)
    invalid = client.post("/api/admin/api-keys", json={
        "name": "bad expiry", "scopes": ["clients:read"], "expires_in_days": 0
    }, headers={"X-CSRF-Token": csrf})
    assert invalid.status_code == 422
    made = client.post("/api/admin/api-keys", json={
        "name": "temporary bot", "scopes": ["clients:read"], "expires_in_days": 1
    }, headers={"X-CSRF-Token": csrf})
    assert made.status_code == 200, made.text
    token = made.json()["token"]
    key_id = made.json()["id"]
    assert made.json()["expires_at"]
    with panel.db() as c:
        c.execute("UPDATE api_keys SET expires_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", key_id))
    expired = client.get("/api/v1/clients", headers={"Authorization": "Bearer " + token})
    assert expired.status_code == 401
    key = next(x for x in client.get("/api/admin/api-keys").json()["keys"] if x["id"] == key_id)
    assert key["enabled"] is False
