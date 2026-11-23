#!/usr/bin/env python3
"""Verify exact realm-management roles in fresh lab service-account tokens."""
import base64
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request


TOKEN_URL = (
    "https://jjdguard-keycloak:8443/sso/realms/jjdguard/"
    "protocol/openid-connect/token"
)
CA_FILE = "/certs/lab-ca.crt"
CASES = (
    (
        "jjdguard-control-plane",
        "IDENTITY_RUNTIME_CLIENT_SECRET",
        ["manage-identity-providers"],
    ),
    (
        "jjdguard-directory-orchestrator",
        "DIRECTORY_RUNTIME_CLIENT_SECRET",
        ["manage-realm", "manage-users", "view-realm"],
    ),
)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def token_roles(client_id: str, secret: str) -> list[str]:
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }
    ).encode("ascii")
    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(
            request, context=ssl.create_default_context(cafile=CA_FILE), timeout=30
        ) as response:
            token = json.load(response)["access_token"]
        segment = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        roles = payload["resource_access"]["realm-management"]["roles"]
    except Exception:
        fail(f"{client_id} token could not be validated")
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        fail(f"{client_id} token roles were malformed")
    return sorted(roles)


for client_id, secret_name, expected in CASES:
    secret = os.environ.get(secret_name, "")
    if not secret or token_roles(client_id, secret) != sorted(expected):
        fail(f"{client_id} token had non-minimal realm-management roles")

print("PASS: runtime service-account tokens contain exact minimum roles")
