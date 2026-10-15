import json

from app.marzban_backend import MarzbanBackend


class FakeClient:
    def __init__(self):
        self.created = []
        self.modified = []
        self.deleted = []
        self.pages = {
            0: {"users": [
                {"username": "ab123", "note": "[AbyssPanel:id-1] First", "status": "active",
                 "expire": 0, "data_limit": 0, "used_traffic": 8, "links": []}
            ], "total": 2},
            1: {"users": [
                {"username": "ab456", "note": "[AbyssPanel:id-2] Second", "status": "disabled",
                 "expire": 0, "data_limit": 1024, "used_traffic": 2, "links": []}
            ], "total": 2},
        }

    def users(self, offset=0, limit=100):
        assert limit == 100
        return self.pages[offset]

    def create_user(self, payload):
        self.created.append(payload)
        return {**payload, "status": payload["status"], "used_traffic": 0,
                "created_at": "2026-01-01T00:00:00", "subscription_url": "https://sub.test/sub/token"}

    def modify_user(self, username, payload):
        self.modified.append((username, payload))
        return {"username": username, "note": "[AbyssPanel:id-1] First", "status": payload.get("status", "active"),
                "expire": payload.get("expire", 0), "data_limit": payload.get("data_limit", 0),
                "used_traffic": 0, "links": []}

    def delete_user(self, username):
        self.deleted.append(username)

    def system(self):
        return {"version": "test"}

    def subscription_url(self, username):
        return "https://sub.test/sub/token"


def test_backend_paginates_users():
    api = FakeClient()
    backend = MarzbanBackend(api)
    users = backend.list_users()
    assert [u["id"] for u in users] == ["id-1", "id-2"]
    assert [u["enabled"] for u in users] == [True, False]


def test_backend_create_update_delete(monkeypatch):
    monkeypatch.setenv("MARZBAN_INBOUNDS_JSON", json.dumps({"vless": ["VLESS WS"]}))
    api = FakeClient()
    backend = MarzbanBackend(api)
    created = backend.create_user(client_id="id-1", name="First", duration_days=2, quota_gb=1)
    assert created["id"] == "id-1"
    assert api.created[0]["data_limit"] == 1024**3
    updated = backend.update_user("ab123", enabled=False, quota_gb=2)
    assert updated["enabled"] is False
    assert api.modified[0][0] == "ab123"
    assert api.modified[0][1]["data_limit"] == 2 * 1024**3
    backend.delete_user("ab123")
    assert api.deleted == ["ab123"]
    assert backend.subscription_url("ab123") == "https://sub.test/sub/token"


def test_backend_update_requires_a_change():
    backend = MarzbanBackend(FakeClient())
    import pytest
    with pytest.raises(ValueError, match="No supported"):
        backend.update_user("ab123")
