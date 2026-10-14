import asyncio
import base64
import html
import os
import re
import sqlite3
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


def test_fresh_install_uses_requested_admin_default(client, tmp_path):
    credential_file = tmp_path / "INITIAL_ADMIN_PASSWORD.txt"
    assert credential_file.exists()
    assert "Username: admin" in credential_file.read_text(encoding="utf-8")
    assert "Password: admin" in credential_file.read_text(encoding="utf-8")


def test_dashboard_is_not_cached_and_has_section_navigation(client):
    login_page = client.get("/login")
    assert 'id="abyss-theme-system"' in login_page.text
    assert 'id="abyss-theme-polish"' in login_page.text
    assert 'id="abyss-theme-controller"' in login_page.text
    assert 'data-abyss-theme="angel"' in login_page.text
    admin_client(client)
    response = client.get("/")
    assert response.status_code == 200
    assert "no-store" in response.headers.get("cache-control", "")
    assert '/dashboard.js?v=20261014-ui3' in response.text
    assert 'id="abyss-theme-system"' in response.text
    assert 'id="abyss-theme-polish"' in response.text
    assert 'id="abyss-theme-controller"' in response.text
    assert 'سلطنتی · مشکی و طلایی' in response.text
    assert 'سپید · فرشته‌گون' in response.text
    assert 'id="sidebar"' in response.text
    assert 'data-section-page="clients"' in response.text
    assert 'id="metricsCard"' in response.text
    assert 'id="adminUsersCard"' in response.text
    assert 'id="apiKeysCard"' in response.text


def test_dashboard_requires_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/api/overview").status_code == 401


def test_create_pause_subscription_and_revoke(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}

    created = client.post("/api/clients", json={"name": "Test client", "duration_days": 30, "quota_gb": 10}, headers=headers)
    assert created.status_code == 200, created.text
    client_id = created.json()["id"]

    overview = client.get("/api/overview").json()
    assert overview["total"] == 1
    assert overview["active"] == 1
    row = overview["clients"][0]
    assert row["quota_bytes"] == 10 * 1024**3
    assert row["expires_at"]

    link = client.get(f"/api/clients/{client_id}/subscription")
    assert link.status_code == 200
    assert link.json()["url"].startswith("https://")

    subscription = client.get(link.json()["url"].replace("https://testserver", "http://testserver"))
    assert subscription.status_code == 200
    configs = base64.b64decode(subscription.text).decode().splitlines()
    assert len(configs) == 12
    assert sum(line.startswith("vless://") for line in configs) == 10
    assert sum(line.startswith("trojan://") for line in configs) == 1
    assert sum(line.startswith("vmess://") for line in configs) == 1
    assert sum(line.startswith("ss://") for line in configs) == 0
    assert any("type=ws" in line for line in configs)
    assert any("type=httpupgrade" in line for line in configs)
    assert sum("type=xhttp" in line for line in configs) == 6
    assert any("mode=auto" in line for line in configs)
    assert any("mode=packet-up" in line for line in configs)
    assert sum("mode=packet-up" in line for line in configs) == 1
    assert sum("mode=stream-up" in line for line in configs) == 2
    assert sum("mode=stream-one" in line for line in configs) == 2
    assert not any(line.startswith("ss://") for line in configs)

    paused = client.patch(f"/api/clients/{client_id}", json={"enabled": False}, headers=headers)
    assert paused.status_code == 200
    assert client.get(f"/sub/{_token_from_url(link.json()['url'])}").status_code == 404

    enabled = client.patch(f"/api/clients/{client_id}", json={"enabled": True}, headers=headers)
    assert enabled.status_code == 200

    revoked = client.delete(f"/api/clients/{client_id}", headers=headers)
    assert revoked.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0


def test_same_subscription_url_serves_branded_page_to_browsers(client):
    csrf = admin_client(client)
    created = client.post("/api/clients", json={"name": "Unified URL", "duration_days": 30, "quota_gb": 4},
                          headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    url = client.get(f"/api/clients/{created.json()['id']}/subscription").json()["url"]
    path = url.replace("https://testserver", "")
    browser = client.get(path, headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "Mozilla/5.0 Chrome/130"})
    assert browser.status_code == 200
    assert "text/html" in browser.headers["content-type"]
    assert "Unified URL" in browser.text
    assert 'id="abyss-theme-system"' in browser.text
    assert 'id="abyss-theme-polish"' in browser.text
    assert 'id="abyss-theme-controller"' in browser.text
    assert "no-store" in browser.headers["cache-control"]
    subscription_client = client.get(path, headers={"Accept": "*/*", "User-Agent": "v2rayNG"})
    assert subscription_client.status_code == 200
    assert "text/plain" in subscription_client.headers["content-type"]
    configs = base64.b64decode(subscription_client.text).decode().splitlines()
    assert len(configs) == 12
    assert "Accept, User-Agent" in subscription_client.headers["vary"]
    assert "Subscription-Userinfo" in subscription_client.headers
    assert "total=4294967296" in subscription_client.headers["Subscription-Userinfo"]
    assert client.get(f"/api/clients/{created.json()['id']}/subscription").json()["page_url"] == url


def test_diagnostics_endpoints_require_auth_and_report_profiles(client):
    assert client.get("/api/system/diagnostics").status_code == 401
    csrf = admin_client(client)
    result = client.get("/api/system/diagnostics?carrier=irancell")
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["carrier"] == "irancell"
    assert data["carrier_label"] == "ایرانسل"
    assert len(data["profiles"]) == 12
    assert any(x["key"] == "xhttp_stream_up" and x["mode"] == "stream-up" for x in data["profiles"])
    assert any(x["key"] == "xhttp_stream_one" and x["mode"] == "stream-one" for x in data["profiles"])
    assert not any(x["key"] == "ss_ws" for x in data["profiles"])
    repaired = client.post("/api/system/diagnostics/repair", json={}, headers={"X-CSRF-Token": csrf})
    assert repaired.status_code == 200, repaired.text
    assert repaired.json()["ok"] is True


def test_subscription_feedback_is_aggregated_by_carrier(client, monkeypatch):
    csrf = admin_client(client)
    created = client.post("/api/clients", json={"name": "Feedback test"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    token = client.get(f"/api/clients/{created.json()['id']}/subscription").json()["url"].rsplit("/", 1)[1]

    class FakeResponse:
        status = 400
        def read(self, *args, **kwargs): return b""
    class FakeConnection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return FakeResponse()
        def close(self): pass
    monkeypatch.setattr(panel.http.client, "HTTPConnection", FakeConnection)

    first = client.post(f"/sub/{token}/feedback", json={"carrier": "irancell", "profile_key": "ws", "result": "ok"})
    assert first.status_code == 200, first.text
    report = client.get("/api/system/diagnostics?carrier=irancell").json()
    ws = next(x for x in report["profiles"] if x["key"] == "ws")
    assert ws["feedback_reports"] == 1
    assert ws["feedback_success_rate"] == 100

    updated = client.post(f"/sub/{token}/feedback", json={"carrier": "irancell", "profile_key": "ws", "result": "fail"})
    assert updated.status_code == 200, updated.text
    report = client.get("/api/system/diagnostics?carrier=irancell").json()
    ws = next(x for x in report["profiles"] if x["key"] == "ws")
    assert ws["feedback_reports"] == 1
    assert ws["feedback_success_rate"] == 0
    assert client.post(f"/sub/{token}/feedback", json={"carrier": "invalid", "profile_key": "ws", "result": "ok"}).status_code == 422


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


def test_xray_config_has_unique_inbounds_and_stats_api(client):
    admin_client(client)
    csrf = client.get("/api/overview").json()["csrf"]
    created = client.post("/api/clients", json={"name": "Config test"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200
    config = panel.make_xray_config()
    inbounds = config["inbounds"]
    assert len(inbounds) == 13  # Stats API plus twelve selectable profiles
    assert len({item["tag"] for item in inbounds}) == len(inbounds)
    assert len({item["port"] for item in inbounds}) == len(inbounds)
    assert config["api"]["services"] == ["StatsService"]
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
    assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True
    xhttp = [item for item in inbounds if item.get("streamSettings", {}).get("network") == "xhttp"]
    assert {item["streamSettings"]["xhttpSettings"]["mode"] for item in xhttp} == {"auto", "packet-up", "stream-up", "stream-one"}
    assert not any(item.get("protocol") == "shadowsocks" for item in inbounds)


def test_subscription_landing_page_and_qr_are_responsive_and_private(client):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Portal user", "duration_days": 14, "quota_gb": 8},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    info = client.get(f"/api/clients/{cid}/subscription").json()
    assert info["url"].startswith("https://testserver/sub/")
    assert info["page_url"] == info["url"] and info["page_url"].startswith("https://testserver/sub/")
    assert info["qr_url"].endswith("/qr")

    page = client.get(info["page_url"].replace("https://testserver", "http://testserver"), headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": "Mozilla/5.0 Chrome/130"})
    assert page.status_code == 200
    assert "viewport-fit=cover" in page.text
    assert "Abyss Tunnel" in page.text
    assert 'id="abyss-theme-polish"' in page.text
    assert "Portal user" in page.text
    assert "xhttp-auto" in page.text and "xhttp-packet-up" in page.text
    assert "xhttp-stream-up" in page.text and "xhttp-stream-one" in page.text
    assert "xhttp-stream-up-alt" in page.text and "xhttp-stream-one-alt" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert "noindex, nofollow" in page.headers["x-robots-tag"]

    qr = client.get(info["qr_url"].replace("https://testserver", "http://testserver"))
    assert qr.status_code == 200
    assert "image/svg+xml" in qr.headers["content-type"]
    assert b"<svg" in qr.content
    assert qr.headers["cache-control"] == "no-store"

    paused = client.patch(f"/api/clients/{cid}", json={"enabled": False}, headers={"X-CSRF-Token": csrf})
    assert paused.status_code == 200
    assert client.get(f"/s/{info['url'].rsplit('/', 1)[1]}").status_code == 404
    assert client.get(f"/sub/{info['url'].rsplit('/', 1)[1]}/qr").status_code == 404


def test_edit_client_and_reset_usage(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/clients",
        json={"name": "Before", "duration_days": 7, "quota_gb": 5, "note": "old"},
        headers=headers,
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (12345, cid))

    edited = client.patch(
        f"/api/clients/{cid}",
        json={"name": "After", "note": "new", "duration_days": 21, "quota_gb": 12},
        headers=headers,
    )
    assert edited.status_code == 200
    row = client.get("/api/overview").json()["clients"][0]
    assert row["name"] == "After"
    assert row["note"] == "new"
    assert row["quota_bytes"] == 12 * 1024**3
    assert row["used_bytes"] == 12345
    assert row["expires_at"]

    reset = client.post(f"/api/clients/{cid}/reset-usage", headers=headers)
    assert reset.status_code == 200
    assert client.get("/api/overview").json()["clients"][0]["used_bytes"] == 0

    unlimited = client.patch(
        f"/api/clients/{cid}",
        json={"duration_days": None, "quota_gb": None},
        headers=headers,
    )
    assert unlimited.status_code == 200
    row = client.get("/api/overview").json()["clients"][0]
    assert row["expires_at"] is None
    assert row["quota_bytes"] is None


def test_failed_revoke_restores_usage_and_limits(client, monkeypatch):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/clients",
        json={"name": "Rollback metadata", "duration_days": 20, "quota_gb": 7},
        headers=headers,
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=34567 WHERE id=?", (cid,))
    before = client.get("/api/overview").json()["clients"][0]

    calls = {"count": 0}
    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")
    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)

    response = client.delete(f"/api/clients/{cid}", headers=headers)
    assert response.status_code == 503
    after = client.get("/api/overview").json()["clients"][0]
    assert after["id"] == before["id"]
    assert after["expires_at"] == before["expires_at"]
    assert after["quota_bytes"] == before["quota_bytes"]
    assert after["used_bytes"] == 34567


def test_expiry_monitor_disables_expired_client(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired test"},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))

    fake_xray = tmp_path / "xray-expiry"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    class RunningProcess:
        def poll(self): return None
        def terminate(self): return None
    monkeypatch.setattr(panel, "xray_proc", RunningProcess())
    monkeypatch.setattr(panel, "read_xray_stats", lambda: {})
    async def fake_restart(): return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    row = client.get("/api/overview").json()["clients"][0]
    assert not row["enabled"]


def test_profile_settings_update_xray_and_subscription(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Profile test"}, headers=headers)
    assert created.status_code == 200
    cid = created.json()["id"]

    settings = client.get("/api/settings")
    assert settings.status_code == 200
    assert len(settings.json()["profiles"]) == 12
    assert all(p["enabled"] for p in settings.json()["profiles"])

    changed = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"ws": False, "xhttp_packet_up": False}},
        headers=headers,
    )
    assert changed.status_code == 200
    assert {p["key"] for p in changed.json()["profiles"] if p["enabled"]} == {"httpupgrade", "xhttp_auto", "xhttp_stream_up", "xhttp_stream_one", "trojan_ws", "vmess_ws", "ws_alt", "httpupgrade_alt", "xhttp_stream_up_alt", "xhttp_stream_one_alt"}
    config = panel.make_xray_config()
    assert 10001 not in {i["port"] for i in config["inbounds"]}
    assert 10004 not in {i["port"] for i in config["inbounds"]}

    info = client.get(f"/api/clients/{cid}/subscription").json()
    raw = client.get(info["url"].replace("https://testserver", "http://testserver"))
    links = base64.b64decode(raw.text).decode().splitlines()
    assert len(links) == 9
    assert not any("#abysstunnel-Profile%20test-ws" in line for line in links)
    assert any("mode=packet-up" in line for line in links)

    rejected = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"httpupgrade": False, "xhttp_auto": False, "xhttp_stream_up": False, "xhttp_stream_one": False, "trojan_ws": False, "vmess_ws": False, "ss_ws": False, "ws_alt": False, "httpupgrade_alt": False}},
        headers=headers,
    )
    assert rejected.status_code == 422


def test_profile_settings_roll_back_if_xray_fails(client, monkeypatch):
    csrf = admin_client(client)
    calls = {"count": 0}
    async def fail_once_then_recover():
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("simulated Xray failure")
        panel.XRAY_CONFIG.write_text('{"recovered": true}', encoding="utf-8")
    monkeypatch.setattr(panel, "start_xray", fail_once_then_recover)

    response = client.patch(
        "/api/settings/profiles",
        json={"profiles": {"ws": False}},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 503
    assert panel.get_profile_flags()["ws"] is True
    assert 10001 in {i["port"] for i in panel.make_xray_config()["inbounds"]}
    assert calls["count"] == 2


def test_usage_monitor_enforces_quota(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Quota test", "quota_gb": 1},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET used_bytes=? WHERE id=?", (1024**3 - 10, cid))

    fake_xray = tmp_path / "xray"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    class RunningProcess:
        def poll(self): return None
        def terminate(self): return None
    monkeypatch.setattr(panel, "xray_proc", RunningProcess())
    monkeypatch.setattr(panel, "read_xray_stats", lambda: {cid: 20})
    async def fake_restart(): return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    row = client.get("/api/overview").json()["clients"][0]
    assert row["used_bytes"] == 1024**3 + 10
    assert not row["enabled"]


def test_password_change_removes_initial_credential_file(client, tmp_path):
    csrf = admin_client(client)
    initial_file = tmp_path / "INITIAL_ADMIN_PASSWORD.txt"
    assert initial_file.exists()
    changed = client.post(
        "/api/password",
        json={"current_password": "admin", "new_password": "SecureAbyssPass2026"},
        headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200
    assert not initial_file.exists()

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "admin", "password": "SecureAbyssPass2026", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_dashboard_has_persian_english_toggle(client):
    csrf = admin_client(client)
    page = client.get("/")
    assert page.status_code == 200
    assert 'lang="fa" dir="rtl"' in page.text
    script = client.get("/dashboard.js")
    assert script.status_code == 200
    assert "toggleLanguage" in script.text
    assert "localStorage.setItem('abyss-lang',lang)" in script.text
    assert "fa:" in script.text and "en:" in script.text


def test_nginx_xhttp_uses_prefix_locations():
    config = (Path(__file__).resolve().parents[1] / "nginx" / "default.conf").read_text(encoding="utf-8")
    assert "location ^~ /xhttp {" in config
    assert "location ^~ /xhttp-packet {" in config
    assert "location = /xhttp {" not in config
    assert "location = /xhttp-packet {" not in config

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True, "xray": "running"}


def test_reseller_login_is_scoped_and_cannot_overallocate(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/resellers",
        json={"username": "reseller_one", "password": "StrongPassword123", "quota_gb": 2},
        headers=headers,
    )
    assert created.status_code == 200, created.text
    assert created.json()["quota_bytes"] == 2 * 1024**3

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "reseller_one", "password": "StrongPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    csrf = client.get("/api/overview").json()["csrf"]
    headers = {"X-CSRF-Token": csrf}

    own = client.post("/api/clients", json={"name": "Owned", "quota_gb": 1}, headers=headers)
    assert own.status_code == 200, own.text
    assert client.get("/api/overview").json()["total"] == 1
    too_large = client.post("/api/clients", json={"name": "Too large", "quota_gb": 2}, headers=headers)
    assert too_large.status_code == 422

    # A reseller cannot operate on another account's client by guessing its ID.
    assert client.patch("/api/clients/not-owned", json={"enabled": False}, headers=headers).status_code == 404
    # Resellers cannot alter global Xray profiles or download/restore the whole database.
    assert client.patch("/api/settings/profiles", json={"profiles": {"ws": False}}, headers=headers).status_code == 403
    assert client.get("/api/backup").status_code == 403


def test_backup_and_restore_round_trip(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Backup me", "quota_gb": 2}, headers=headers)
    assert created.status_code == 200
    backup = client.get("/api/backup")
    assert backup.status_code == 200
    assert "application/zip" in backup.headers["content-type"]

    deleted = client.delete(f"/api/clients/{created.json()['id']}", headers=headers)
    assert deleted.status_code == 200
    assert client.get("/api/overview").json()["total"] == 0

    restored = client.post("/api/backup/restore", files={"backup": ("backup.zip", backup.content, "application/zip")}, headers=headers)
    assert restored.status_code == 200, restored.text
    assert client.get("/api/overview").json()["total"] == 1

def test_nested_reseller_allocation_is_atomic_and_scoped(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    parent = client.post(
        "/api/resellers",
        json={"username": "parent_reseller", "password": "ParentPassword123", "quota_gb": 2},
        headers=headers,
    )
    assert parent.status_code == 200, parent.text

    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "parent_reseller", "password": "ParentPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    csrf = client.get("/api/overview").json()["csrf"]
    headers = {"X-CSRF-Token": csrf}

    child = client.post(
        "/api/resellers",
        json={"username": "child_reseller", "password": "ChildPassword123", "quota_gb": 1},
        headers=headers,
    )
    assert child.status_code == 200, child.text
    edited = client.patch(
        f"/api/resellers/{child.json()['id']}",
        json={"username": "child_renamed", "password": "ChangedPassword123", "quota_gb": 1},
        headers=headers,
    )
    assert edited.status_code == 200, edited.text
    too_much = client.post(
        "/api/resellers",
        json={"username": "oversized_child", "password": "OtherPassword123", "quota_gb": 1.1},
        headers=headers,
    )
    assert too_much.status_code == 422
    listed = client.get("/api/resellers").json()["resellers"]
    assert listed[0]["id"] == child.json()["id"]
    assert listed[0]["username"] == "child_renamed"

    # Simulate two simultaneous allocation attempts competing for the same
    # final GB. SQLite BEGIN IMMEDIATE must serialize the quota check + insert.
    from concurrent.futures import ThreadPoolExecutor
    def create_one(index):
        return client.post(
            "/api/clients",
            json={"name": f"Concurrent {index}", "quota_gb": 1},
            headers=headers,
        ).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(create_one, range(2)))
    assert sorted(statuses) == [200, 422], statuses
    assert client.get("/api/overview").json()["total"] == 1

    # Parent account suspension must invalidate the child's session too.
    client.get("/logout")
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    login = client.post(
        "/login",
        data={"username": "child_renamed", "password": "ChangedPassword123", "csrf_token": html.unescape(token)},
        follow_redirects=False,
    )
    assert login.status_code == 303
    child_csrf = client.get("/api/overview").json()["csrf"]
    own_client = client.post(
        "/api/clients",
        json={"name": "Child-owned client", "quota_gb": 1},
        headers={"X-CSRF-Token": child_csrf},
    )
    assert own_client.status_code == 200, own_client.text
    assert client.get("/api/overview").json()["total"] == 1
    over_child_quota = client.post(
        "/api/clients",
        json={"name": "Over child quota", "quota_gb": 1},
        headers={"X-CSRF-Token": child_csrf},
    )
    assert over_child_quota.status_code == 422

    with panel.db() as conn:
        conn.execute("UPDATE resellers SET enabled=0 WHERE id=?", (parent.json()["id"],))
    assert client.get("/api/overview").status_code == 401


def test_restore_rejects_corrupt_database_without_replacing_current(client):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Keep me", "quota_gb": 2}, headers=headers)
    assert created.status_code == 200
    before = client.get("/api/overview").json()["total"]
    response = client.post(
        "/api/restore",
        content=b"not a sqlite database",
        headers={**headers, "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 422
    assert client.get("/api/overview").json()["total"] == before


def test_expiry_is_enforced_while_xray_is_stopped(client, monkeypatch, tmp_path):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired during outage"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 200
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))
    fake_xray = tmp_path / "xray-not-running"
    fake_xray.write_text("test", encoding="utf-8")
    monkeypatch.setattr(panel, "XRAY_BIN", str(fake_xray))
    monkeypatch.setattr(panel, "xray_proc", None)
    monkeypatch.setattr(panel, "read_xray_stats", lambda: pytest.fail("must not query a stopped Xray process"))
    async def fake_restart():
        return None
    monkeypatch.setattr(panel, "start_xray", fake_restart)

    asyncio.run(panel.enforce_client_limits())
    with panel.db() as conn:
        row = conn.execute("SELECT enabled FROM clients WHERE id=?", (cid,)).fetchone()
    assert row["enabled"] == 0


def test_expired_client_is_not_served_a_subscription(client):
    csrf = admin_client(client)
    created = client.post(
        "/api/clients",
        json={"name": "Expired subscription"},
        headers={"X-CSRF-Token": csrf},
    )
    cid = created.json()["id"]
    with panel.db() as conn:
        conn.execute("UPDATE clients SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (cid,))
        token = conn.execute("SELECT sub_token FROM clients WHERE id=?", (cid,)).fetchone()["sub_token"]
    response = client.get(f"/sub/{token}")
    assert response.status_code == 404


def test_restore_rejects_valid_sqlite_with_incompatible_schema(client, tmp_path):
    csrf = admin_client(client)
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/clients", json={"name": "Preserve current DB", "quota_gb": 1}, headers=headers)
    assert created.status_code == 200
    bad_path = tmp_path / "incompatible.sqlite3"
    conn = sqlite3.connect(bad_path)
    try:
        conn.execute("CREATE TABLE admins (id INTEGER PRIMARY KEY, password TEXT)")
        conn.execute("CREATE TABLE clients (id TEXT)")
        conn.execute("CREATE TABLE settings (key TEXT, value TEXT)")
        conn.commit()
    finally:
        conn.close()
    response = client.post(
        "/api/restore",
        content=bad_path.read_bytes(),
        headers={**headers, "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 422
    assert client.get("/api/overview").json()["total"] == 1


def test_health_reports_stopped_xray_as_unhealthy(client, monkeypatch):
    monkeypatch.setattr(panel, "XRAY_BIN", "/bin/sh")
    monkeypatch.setattr(panel, "xray_proc", None)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json() == {"ok": False, "xray": "stopped"}


def test_invalid_expiry_metadata_fails_closed():
    assert panel.client_is_expired("not-a-timestamp")
    assert not panel.client_is_expired(None)

