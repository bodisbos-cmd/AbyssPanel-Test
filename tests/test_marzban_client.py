import httpx
import pytest

from app.marzban_client import MarzbanClient, MarzbanError


def fake_client(handler):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return MarzbanClient("https://marzban.test", "admin", "secret", client=http), http


def test_authenticates_and_calls_users_api():
    seen = []
    def handler(request):
        seen.append(request)
        if request.url.path == "/api/admin/token":
            assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
            return httpx.Response(200, json={"access_token": "token"})
        assert request.headers["authorization"] == "Bearer token"
        return httpx.Response(200, json={"users": [], "total": 0})
    api, http = fake_client(handler)
    try:
        assert api.users(limit=20) == {"users": [], "total": 0}
        assert [r.url.path for r in seen] == ["/api/admin/token", "/api/users"]
    finally:
        http.close()


def test_reauthenticates_once_on_401():
    auth_count = 0
    api_calls = 0
    def handler(request):
        nonlocal auth_count, api_calls
        if request.url.path == "/api/admin/token":
            auth_count += 1
            return httpx.Response(200, json={"access_token": f"token-{auth_count}"})
        api_calls += 1
        if api_calls == 1:
            return httpx.Response(401, json={"detail": "expired"})
        assert request.headers["authorization"] == "Bearer token-2"
        return httpx.Response(200, json={"status": "ok"})
    api, http = fake_client(handler)
    try:
        assert api.request("GET", "/api/system") == {"status": "ok"}
        assert (auth_count, api_calls) == (2, 2)
    finally:
        http.close()


def test_auth_failure_is_not_retried_and_body_is_not_leaked():
    api, http = fake_client(lambda request: httpx.Response(
        401, json={"detail": "bad credentials", "password": "secret"}))
    try:
        with pytest.raises(MarzbanError) as error:
            api.system()
        assert error.value.status_code == 401
        assert "secret" not in str(error.value)
    finally:
        http.close()


def test_validates_user_pagination():
    api, http = fake_client(lambda request: httpx.Response(200, json={}))
    try:
        with pytest.raises(ValueError):
            api.users(limit=0)
    finally:
        http.close()
