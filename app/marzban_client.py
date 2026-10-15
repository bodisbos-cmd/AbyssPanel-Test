"""Small, typed HTTP client for the official Marzban REST API.

This is an integration foundation only; the existing AbyssPanel routes must call
this adapter before MARZBAN_BACKEND can safely be enabled.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any
from urllib.parse import urljoin

import httpx


class MarzbanError(RuntimeError):
    """A safe, user-facing Marzban integration error."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class MarzbanClient:
    """Authenticated Marzban REST client with token refresh and bounded timeouts."""

    def __init__(self, base_url: str, username: str, password: str, *,
                 timeout: float = 12.0, client: httpx.Client | None = None) -> None:
        base_url = base_url.strip().rstrip("/")
        if not base_url:
            raise ValueError("Marzban base URL is required")
        if not username or not password:
            raise ValueError("Marzban admin credentials are required")
        self.base_url = base_url + "/"
        self.username, self.password, self.timeout = username, password, timeout
        self._http = client or httpx.Client(timeout=timeout, follow_redirects=False)
        self._owns_client = client is None
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._lock = threading.RLock()

    @classmethod
    def from_env(cls) -> "MarzbanClient":
        return cls(os.getenv("MARZBAN_BASE_URL", ""),
                   os.getenv("MARZBAN_ADMIN_USERNAME", ""),
                   os.getenv("MARZBAN_ADMIN_PASSWORD", ""),
                   timeout=float(os.getenv("MARZBAN_TIMEOUT_SECONDS", "12")))

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _login(self, *, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.monotonic() < self._token_expires_at:
                return self._token
            try:
                response = self._http.post(
                    self._url("/api/admin/token"),
                    data={"username": self.username, "password": self.password},
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
            except httpx.HTTPError as exc:
                raise MarzbanError("Cannot connect to Marzban API") from exc
            if response.status_code != 200:
                raise MarzbanError("Marzban authentication failed", response.status_code)
            try:
                token = response.json()["access_token"]
            except (ValueError, KeyError, TypeError) as exc:
                raise MarzbanError("Marzban returned an invalid authentication response") from exc
            if not isinstance(token, str) or not token:
                raise MarzbanError("Marzban returned an empty access token")
            self._token = token
            self._token_expires_at = time.monotonic() + 20 * 60
            return token

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Call an endpoint; retry once after a 401 and never expose raw error bodies."""
        extra_headers = dict(kwargs.pop("headers", {}) or {})
        for attempt in range(2):
            token = self._login(force=attempt == 1)
            headers = {**extra_headers, "Authorization": f"Bearer {token}"}
            try:
                response = self._http.request(method.upper(), self._url(path),
                                               headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise MarzbanError("Cannot connect to Marzban API") from exc
            if response.status_code == 401 and attempt == 0:
                with self._lock:
                    self._token, self._token_expires_at = None, 0
                continue
            if response.status_code >= 400:
                detail = "Marzban API request failed"
                try:
                    payload = response.json()
                    if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
                        detail = payload["detail"][:240]
                except ValueError:
                    pass
                raise MarzbanError(detail, response.status_code)
            if response.status_code == 204 or not response.content:
                return None
            if "json" in response.headers.get("content-type", ""):
                try:
                    return response.json()
                except ValueError as exc:
                    raise MarzbanError("Marzban returned invalid JSON") from exc
            return response.text
        raise MarzbanError("Marzban authentication expired", 401)

    def system(self) -> dict[str, Any]:
        result = self.request("GET", "/api/system")
        return result if isinstance(result, dict) else {}

    def users(self, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        if offset < 0 or not 1 <= limit <= 1000:
            raise ValueError("offset must be >= 0 and limit must be between 1 and 1000")
        result = self.request("GET", "/api/users", params={"offset": offset, "limit": limit})
        return result if isinstance(result, dict) else {}

    def get_user(self, username: str) -> dict[str, Any]:
        return self.request("GET", f"/api/user/{username}")

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", "/api/user", json=payload)

    def modify_user(self, username: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("PUT", f"/api/user/{username}", json=payload)

    def delete_user(self, username: str) -> None:
        self.request("DELETE", f"/api/user/{username}")

    def subscription_url(self, username: str) -> str:
        user = self.get_user(username)
        value = user.get("subscription_url")
        if not isinstance(value, str) or not value:
            raise MarzbanError("Marzban user has no subscription URL")
        return value
