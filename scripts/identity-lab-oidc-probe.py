#!/usr/bin/env python3
"""Verify selected claims in a real JJDGuard authorization-code token."""
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

JJD_BASE = "https://jjdguard-keycloak:8443/sso"
ENTERPRISE_BASE = "https://enterprise-keycloak:8443"
PROVIDER = os.environ.get("IDENTITY_TEST_PROVIDER", "enterprise-sso")
REDIRECT_URI = f"http://identity-portal:3100/chat/api/auth/callback/{PROVIDER}"
CLIENT_ID = "enterprise-ai-portal"
EXPECTED_EMAIL = os.environ.get("IDENTITY_EXPECT_EMAIL", "enterprise-erin@enterprise-lab.test")
EXPECTED_GROUP = os.environ.get("IDENTITY_EXPECT_GROUP", "")
EXPECTED_DEPARTMENT = os.environ.get("IDENTITY_EXPECT_DEPARTMENT", "")
IDP_HINT = os.environ.get("IDENTITY_TEST_IDP_HINT", "enterprise")


def fail(stage: str) -> None:
    print(f"FAIL: OIDC claims probe {stage}", file=sys.stderr)
    raise SystemExit(1)


class LoginForm(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action = ""
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and not self.action and values.get("action"):
            self.action = values["action"] or ""
        if tag == "input" and values.get("name"):
            self.fields[values["name"] or ""] = values.get("value") or ""


class StopAtPortalCallback(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.location = ""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        parsed = urllib.parse.urlparse(newurl)
        if parsed.hostname == "identity-portal" and parsed.port == 3100 and parsed.path == f"/chat/api/auth/callback/{PROVIDER}":
            self.location = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def open_request(opener, request, redirect, stage):  # noqa: ANN001
    try:
        return opener.open(request, timeout=20)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308) and redirect.location:
            return exc
        fail(stage)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError):
        fail(stage)


def decode_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        fail("returned a malformed ID token")
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        value = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        fail("returned an unreadable ID token")
    if not isinstance(value, dict):
        fail("returned invalid claims")
    return value


def main() -> None:
    username = os.environ.get(
        "IDENTITY_TEST_USERNAME",
        os.environ.get("ENTERPRISE_OIDC_TEST_USERNAME", ""),
    )
    password = os.environ.get(
        "IDENTITY_TEST_PASSWORD",
        os.environ.get("ENTERPRISE_OIDC_TEST_PASSWORD", ""),
    )
    client_secret = os.environ.get("PORTAL_OIDC_CLIENT_SECRET", "")
    if not username or not password or not client_secret:
        fail("credentials are not configured")

    verifier = b64url(secrets.token_bytes(48))
    state = b64url(secrets.token_bytes(24))
    nonce = b64url(secrets.token_bytes(24))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    redirect = StopAtPortalCallback()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile="/certs/lab-ca.crt")
        ),
        redirect,
    )
    query_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile groups",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if IDP_HINT:
        query_params["kc_idp_hint"] = IDP_HINT
    query = urllib.parse.urlencode(query_params)
    response = open_request(
        opener,
        urllib.request.Request(
            f"{JJD_BASE}/realms/jjdguard/protocol/openid-connect/auth?{query}"
        ),
        redirect,
        "authorize redirect failed",
    )
    expected_login = ENTERPRISE_BASE if IDP_HINT == "enterprise" else JJD_BASE
    if not response.geturl().startswith(expected_login):
        fail("did not reach the configured identity login")

    form = LoginForm()
    form.feed(response.read().decode("utf-8", errors="replace"))
    if not form.action or "username" not in form.fields or "password" not in form.fields:
        fail("identity login form was not found")
    form.fields.update(username=username, password=password)
    open_request(
        opener,
        urllib.request.Request(
            form.action,
            data=urllib.parse.urlencode(form.fields).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        redirect,
        "identity login or callback failed",
    )
    if not redirect.location:
        fail("did not reach the client callback")
    callback = urllib.parse.parse_qs(urllib.parse.urlparse(redirect.location).query)
    if callback.get("state") != [state] or len(callback.get("code", [])) != 1:
        fail("callback state or authorization code is invalid")

    token_body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": client_secret,
        "redirect_uri": REDIRECT_URI,
        "code": callback["code"][0],
        "code_verifier": verifier,
    }).encode("ascii")
    token_response = open_request(
        opener,
        urllib.request.Request(
            f"{JJD_BASE}/realms/jjdguard/protocol/openid-connect/token",
            data=token_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        redirect,
        "authorization code exchange failed",
    )
    try:
        result = json.load(token_response)
    except json.JSONDecodeError:
        fail("token response is not JSON")
    if not result.get("id_token"):
        fail("token response has no ID token")
    claims = decode_claims(result["id_token"])
    if claims.get("iss") != f"{JJD_BASE}/realms/jjdguard":
        fail("ID token issuer is not JJDGuard")
    if not claims.get("sub") or claims.get("email") != EXPECTED_EMAIL:
        fail("ID token does not represent the expected user")
    if claims.get("nonce") != nonce:
        fail("ID token nonce is invalid")
    groups = claims.get("groups")
    if EXPECTED_GROUP and (not isinstance(groups, list) or EXPECTED_GROUP not in groups):
        fail("ID token lacks the expected group")
    if EXPECTED_DEPARTMENT and claims.get("department") != EXPECTED_DEPARTMENT:
        fail("ID token lacks the expected department")
    access_token = result.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        fail("token response has no access token")
    userinfo_response = open_request(
        opener,
        urllib.request.Request(
            f"{JJD_BASE}/realms/jjdguard/protocol/openid-connect/userinfo",
            headers={"Authorization": "Bearer " + access_token},
        ),
        redirect,
        "userinfo request failed",
    )
    try:
        userinfo = json.load(userinfo_response)
    except json.JSONDecodeError:
        fail("userinfo response is not JSON")
    userinfo_groups = userinfo.get("groups") if isinstance(userinfo, dict) else None
    if EXPECTED_GROUP and (
        not isinstance(userinfo_groups, list) or EXPECTED_GROUP not in userinfo_groups
    ):
        fail("userinfo lacks the expected group")
    if EXPECTED_DEPARTMENT and userinfo.get("department") != EXPECTED_DEPARTMENT:
        fail("userinfo lacks the expected department")
    print("PASS: OIDC ID token and userinfo claims verified")


if __name__ == "__main__":
    main()
