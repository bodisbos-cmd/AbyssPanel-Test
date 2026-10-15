import json
from datetime import datetime, timezone

import pytest

from app.marzban_backend import create_payload, map_user, username_for_client


def test_username_is_stable_and_marzban_safe():
    value = username_for_client("b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b")
    assert value == username_for_client("b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b")
    assert value.startswith("ab")
    assert len(value) <= 32
    assert value.isascii() and value.isalnum()


def test_create_payload_requires_explicit_inbounds(monkeypatch):
    monkeypatch.delenv("MARZBAN_INBOUNDS_JSON", raising=False)
    with pytest.raises(Exception, match="MARZBAN_INBOUNDS_JSON"):
        create_payload(client_id="b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b", name="test")


def test_create_payload_maps_limits_and_inbounds(monkeypatch):
    monkeypatch.setenv("MARZBAN_INBOUNDS_JSON", json.dumps({
        "vless": ["VLESS WS", "VLESS Reality"],
        "vmess": ["VMess WS"]
    }))
    payload = create_payload(
        client_id="b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b",
        name="test", note="invoice-1", duration_days=3, quota_gb=2,
        enabled=False,
    )
    assert payload["data_limit"] == 2 * 1024**3
    assert payload["status"] == "disabled"
    assert payload["data_limit_reset_strategy"] == "no_reset"
    assert payload["inbounds"]["vless"] == ["VLESS WS", "VLESS Reality"]
    assert "[AbyssPanel:b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b]" in payload["note"]
    assert payload["expire"] > int(datetime.now(timezone.utc).timestamp())


def test_create_payload_rejects_invalid_inbound_configuration(monkeypatch):
    monkeypatch.setenv("MARZBAN_INBOUNDS_JSON", '{"vless": "not-a-list"}')
    with pytest.raises(Exception, match="non-empty string list"):
        create_payload(client_id="abc", name="test")


def test_map_user_normalizes_usage_expiry_and_status():
    expiry = int(datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp())
    raw = {
        "username": "ab123", "note": "[AbyssPanel:abc-123] Customer | note",
        "status": "active", "expire": expiry, "data_limit": 4096,
        "used_traffic": 1024, "created_at": "2026-01-01T00:00:00",
        "subscription_url": "https://sub.example/sub/token", "links": ["vless://abc"],
    }
    user = map_user(raw)
    assert user["id"] == "abc-123"
    assert user["name"] == "Customer"
    assert user["note"] == "note"
    assert user["enabled"] is True
    assert user["quota_bytes"] == 4096
    assert user["used_bytes"] == 1024
    assert user["subscription_url"].endswith("/token")
    assert user["links"] == ["vless://abc"]
    assert user["expires_at"].startswith("2030-01-01")


def test_map_user_rejects_malformed_response():
    with pytest.raises(Exception, match="invalid username"):
        map_user({"username": "../admin"})


def test_selected_profiles_resolve_only_explicit_mapped_inbounds(monkeypatch):
    monkeypatch.setenv("MARZBAN_INBOUNDS_JSON", json.dumps({
        "vless": ["VLESS WS", "VLESS XHTTP"],
        "vmess": ["VMess WS"],
    }))
    monkeypatch.setenv("MARZBAN_PROFILE_INBOUNDS_JSON", json.dumps({
        "ws": {"vless": ["VLESS WS"]},
        "xhttp_auto": {"vless": ["VLESS XHTTP"]},
    }))
    payload = create_payload(
        client_id="b7f31a2a-82f9-4fca-93a2-2b7e47a61f2b",
        name="test", selected_profiles=["ws", "xhttp_auto"],
    )
    assert payload["inbounds"] == {"vless": ["VLESS WS", "VLESS XHTTP"]}
    assert payload["proxies"] == {"vless": {}}


def test_selected_profile_without_mapping_fails_closed(monkeypatch):
    monkeypatch.setenv("MARZBAN_INBOUNDS_JSON", json.dumps({"vless": ["VLESS WS"]}))
    monkeypatch.delenv("MARZBAN_PROFILE_INBOUNDS_JSON", raising=False)
    with pytest.raises(Exception, match="MARZBAN_PROFILE_INBOUNDS_JSON"):
        create_payload(client_id="abc", name="test", selected_profiles=["ws"])
