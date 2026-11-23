#!/usr/bin/env python3
"""Toggle lab identity capabilities with rollback on partial directory failure."""
import copy
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://jjdguard-keycloak:8443/sso"


class ToggleError(Exception):
    pass


def fail() -> None:
    print("identity capability toggle failed", file=sys.stderr)
    raise SystemExit(1)


def request(opener, method: str, path: str, token: str = "", body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE + path, data=data, headers=headers, method=method
    )
    try:
        with opener.open(req, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ssl.SSLError):
        raise ToggleError() from None


def admin_token(opener) -> str:
    username = os.environ.get("KEYCLOAK_ADMIN_USER", "")
    password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
    if not username or not password:
        raise ToggleError()
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
    ).encode("ascii")
    req = urllib.request.Request(
        BASE + "/realms/master/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener.open(req, timeout=20) as response:
            token = json.load(response).get("access_token", "")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ssl.SSLError):
        raise ToggleError() from None
    if not token:
        raise ToggleError()
    return token


def update_component(opener, token: str, item: dict, expected: str) -> None:
    item = copy.deepcopy(item)
    item.setdefault("config", {})["enabled"] = [expected]
    path = "/admin/realms/jjdguard/components/" + item["id"]
    status, _ = request(opener, "PUT", path, token, item)
    if status not in {204, 200}:
        raise ToggleError()
    status, actual = request(opener, "GET", path, token)
    if status != 200 or actual.get("config", {}).get("enabled") != [expected]:
        raise ToggleError()


def toggle_directories(opener, token: str, enabled: bool) -> None:
    status, components = request(
        opener,
        "GET",
        "/admin/realms/jjdguard/components?type=org.keycloak.storage.UserStorageProvider",
        token,
    )
    targets = [
        item for item in components or []
        if item.get("name") in {"ldap-federation", "ad-federation"}
    ]
    if status != 200 or len(targets) != 2:
        raise ToggleError()
    expected = "true" if enabled else "false"
    attempted: list[tuple[dict, str]] = []
    try:
        for item in targets:
            original = item.get("config", {}).get("enabled", ["true"])[0]
            attempted.append((copy.deepcopy(item), original))
            update_component(opener, token, item, expected)
    except ToggleError:
        rollback_failed = False
        for item, original in reversed(attempted):
            try:
                update_component(opener, token, item, original)
            except ToggleError:
                rollback_failed = True
        if rollback_failed:
            raise ToggleError()
        raise


def toggle_sso(opener, token: str, enabled: bool) -> None:
    path = "/admin/realms/jjdguard/identity-provider/instances/enterprise"
    status, provider = request(opener, "GET", path, token)
    if status != 200 or provider.get("alias") != "enterprise":
        raise ToggleError()
    provider["enabled"] = enabled
    status, _ = request(opener, "PUT", path, token, provider)
    if status not in {204, 200}:
        raise ToggleError()
    status, actual = request(opener, "GET", path, token)
    if status != 200 or actual.get("enabled") is not enabled:
        raise ToggleError()


def main() -> None:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action not in {"directory-disable", "directory-enable", "sso-disable", "sso-enable"}:
        fail()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile="/certs/lab-ca.crt")
        )
    )
    try:
        token = admin_token(opener)
        enabled = action.endswith("-enable")
        if action.startswith("directory-"):
            toggle_directories(opener, token, enabled)
        else:
            toggle_sso(opener, token, enabled)
    except ToggleError:
        fail()


if __name__ == "__main__":
    main()
