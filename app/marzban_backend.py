"""Translate Abyss client lifecycle values to and from the official Marzban API.

This module deliberately does not guess inbound tags. A deployment must provide
MARZBAN_INBOUNDS_JSON so users are created only on explicitly configured inbounds.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .marzban_client import MarzbanClient, MarzbanError

_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
_GB = 1024 ** 3


def configured_inbounds() -> dict[str, list[str]]:
    raw = os.getenv("MARZBAN_INBOUNDS_JSON", "").strip()
    if not raw:
        raise MarzbanError("MARZBAN_INBOUNDS_JSON must explicitly configure available inbounds")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise MarzbanError("MARZBAN_INBOUNDS_JSON must be valid JSON") from exc
    if not isinstance(value, dict) or not value:
        raise MarzbanError("Marzban inbounds must be a non-empty protocol-to-tags object")
    result: dict[str, list[str]] = {}
    for protocol, tags in value.items():
        if protocol not in {"vless", "vmess", "trojan", "shadowsocks"}:
            raise MarzbanError(f"Unsupported Marzban protocol: {protocol}")
        if not isinstance(tags, list) or not tags or any(not isinstance(tag, str) or not tag.strip() for tag in tags):
            raise MarzbanError(f"Inbound tags for {protocol} must be a non-empty string list")
        result[protocol] = list(dict.fromkeys(tag.strip() for tag in tags))
    return result


def username_for_client(client_id: str) -> str:
    """Stable Marzban-safe username; never put a user-provided name in a URL path."""
    try:
        normalized = uuid.UUID(str(client_id)).hex
    except (ValueError, TypeError, AttributeError):
        normalized = uuid.uuid5(uuid.NAMESPACE_URL, str(client_id)).hex
    return "ab" + normalized[:30]


def create_payload(*, client_id: str, name: str, note: str = "",
                   duration_days: int | None = None, quota_gb: float | None = None,
                   enabled: bool = True) -> dict[str, Any]:
    if duration_days is not None and (isinstance(duration_days, bool) or not isinstance(duration_days, int) or not 1 <= duration_days <= 3650):
        raise ValueError("duration_days must be an integer from 1 to 3650")
    if quota_gb is not None and (isinstance(quota_gb, bool) or not isinstance(quota_gb, (int, float)) or not 1 <= quota_gb <= 100000):
        raise ValueError("quota_gb must be between 1 and 100000")
    expiry = 0 if duration_days is None else int(datetime.now(timezone.utc).timestamp()) + duration_days * 86400
    inbound_map = configured_inbounds()
    proxies = {protocol: {} for protocol in inbound_map}
    return {
        "username": username_for_client(client_id),
        "proxies": proxies,
        "inbounds": inbound_map,
        "expire": expiry,
        "data_limit": 0 if quota_gb is None else int(float(quota_gb) * _GB),
        "data_limit_reset_strategy": "no_reset",
        "status": "active" if enabled else "disabled",
        "note": f"[AbyssPanel:{client_id}] {name}" + (f" | {note}" if note else ""),
    }


def map_user(user: dict[str, Any], *, local_id: str | None = None) -> dict[str, Any]:
    """Normalize a Marzban user to the core fields expected by the Abyss UI."""
    if not isinstance(user, dict):
        raise MarzbanError("Marzban returned an invalid user object")
    username = user.get("username")
    if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
        raise MarzbanError("Marzban returned an invalid username")
    note = user.get("note") or ""
    match = re.search(r"\[AbyssPanel:([A-Za-z0-9_-]{1,64})\]", note)
    client_id = local_id or (match.group(1) if match else username)
    expiry = user.get("expire")
    expires_at = None
    if isinstance(expiry, (int, float)) and not isinstance(expiry, bool) and expiry > 0:
        expires_at = datetime.fromtimestamp(expiry, timezone.utc).isoformat(timespec="seconds")
    quota = user.get("data_limit")
    if quota is not None and (not isinstance(quota, (int, float)) or isinstance(quota, bool) or quota < 0):
        raise MarzbanError("Marzban returned an invalid data limit")
    used = user.get("used_traffic", 0)
    if not isinstance(used, (int, float)) or isinstance(used, bool) or used < 0:
        used = 0
    status = str(user.get("status", "disabled")).lower()
    return {
        "id": client_id,
        "name": note.split("] ", 1)[1].split(" | ", 1)[0] if "] " in note else username,
        "enabled": status == "active",
        "created_at": user.get("created_at", ""),
        "note": note.split(" | ", 1)[1] if " | " in note else "",
        "expires_at": expires_at,
        "quota_bytes": int(quota) if quota not in (None, 0) else None,
        "used_bytes": int(used),
        "marzban_username": username,
        "subscription_url": user.get("subscription_url") or "",
        "links": user.get("links") if isinstance(user.get("links"), list) else [],
        "status": status,
    }


class MarzbanBackend:
    """Narrow service layer used by Abyss routes; the UI must not call Marzban directly."""
    def __init__(self, client: MarzbanClient | None = None):
        self.client = client or MarzbanClient.from_env()
        self._owns_client = client is None

    @classmethod
    def from_env(cls) -> "MarzbanBackend":
        return cls()

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def health(self) -> dict[str, Any]:
        system = self.client.system()
        return {"connected": True, "backend": "marzban", "system": system}

    def list_users(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = self.client.users(offset=offset, limit=100)
            users = page.get("users", [])
            if not isinstance(users, list):
                raise MarzbanError("Marzban returned an invalid users list")
            out.extend(map_user(user) for user in users)
            total = page.get("total", len(out))
            if not users or offset + len(users) >= int(total):
                return out
            offset += len(users)

    def create_user(self, *, client_id: str, name: str, note: str = "",
                    duration_days: int | None = None, quota_gb: float | None = None,
                    enabled: bool = True) -> dict[str, Any]:
        payload = create_payload(client_id=client_id, name=name, note=note,
                                 duration_days=duration_days, quota_gb=quota_gb,
                                 enabled=enabled)
        return map_user(self.client.create_user(payload), local_id=client_id)

    def get_user(self, username: str) -> dict[str, Any]:
        return map_user(self.client.get_user(username))

    def update_user(self, username: str, *, enabled: bool | None = None,
                    duration_days: int | None = None, quota_gb: float | None = None,
                    note: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if enabled is not None:
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be boolean")
            payload["status"] = "active" if enabled else "disabled"
        if duration_days is not None:
            if isinstance(duration_days, bool) or not isinstance(duration_days, int) or not 1 <= duration_days <= 3650:
                raise ValueError("duration_days must be an integer from 1 to 3650")
            payload["expire"] = int(datetime.now(timezone.utc).timestamp()) + duration_days * 86400
        if quota_gb is not None:
            if isinstance(quota_gb, bool) or not isinstance(quota_gb, (int, float)) or not 0 <= quota_gb <= 100000 or (0 < quota_gb < 1):
                raise ValueError("quota_gb must be 0 (unlimited) or between 1 and 100000")
            payload["data_limit"] = int(float(quota_gb) * _GB)
        if note is not None:
            payload["note"] = note
        if not payload:
            raise ValueError("No supported Marzban user changes provided")
        return map_user(self.client.modify_user(username, payload))

    def delete_user(self, username: str) -> None:
        self.client.delete_user(username)

    def subscription_url(self, username: str) -> str:
        return self.client.subscription_url(username)
