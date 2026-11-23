#!/usr/bin/env python3
"""Drive Portal Auth.js through Keycloak and verify the authenticated Chat session."""
import html.parser
import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PORTAL_BASE = "http://identity-portal:3100/chat"


def fail(stage: str) -> None:
    print(f"FAIL: Portal authentication {stage}", file=sys.stderr)
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


def open_request(opener, request, stage: str):
    try:
        return opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        target = urllib.parse.urlparse(exc.geturl())
        fail(f"{stage} (HTTP {exc.code} at {target.hostname}{target.path})")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError):
        fail(stage)


def read_json(response, stage: str) -> dict:
    try:
        value = json.load(response)
    except (ValueError, json.JSONDecodeError):
        fail(stage)
    if not isinstance(value, dict):
        fail(stage)
    return value


def portal_sign_in(opener, provider: str, username: str, password: str) -> dict:
    csrf = read_json(
        open_request(opener, f"{PORTAL_BASE}/api/auth/csrf", "CSRF request failed"),
        "CSRF response was invalid",
    ).get("csrfToken")
    if not isinstance(csrf, str) or not csrf:
        fail("CSRF token was missing")

    body = urllib.parse.urlencode(
        {"csrfToken": csrf, "callbackUrl": f"{PORTAL_BASE}/"}
    ).encode("ascii")
    sign_in = urllib.request.Request(
        f"{PORTAL_BASE}/api/auth/signin/{provider}",
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Auth-Return-Redirect": "1",
        },
    )
    authorize_url = read_json(
        open_request(opener, sign_in, "sign-in initiation failed"),
        "sign-in response was invalid",
    ).get("url")
    authorize_query = urllib.parse.parse_qs(urllib.parse.urlparse(authorize_url).query)
    requested_scopes = set(authorize_query.get("scope", [""])[0].split())
    required_scopes = {"openid", "email", "profile", "groups"}
    if not required_scopes.issubset(requested_scopes):
        fail("sign-in did not request the required OIDC scopes")
    if not isinstance(authorize_url, str) or "jjdguard-keycloak:8443/sso/realms/jjdguard" not in authorize_url:
        fail("sign-in did not reach JJDGuard Keycloak")

    login_page = open_request(opener, authorize_url, "authorization redirect failed")
    form = LoginForm()
    form.feed(login_page.read().decode("utf-8", errors="replace"))
    if not form.action or "username" not in form.fields or "password" not in form.fields:
        fail("Keycloak login form was not found")
    form.fields.update(username=username, password=password)
    submitted = open_request(
        opener,
        urllib.request.Request(
            form.action,
            data=urllib.parse.urlencode(form.fields).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ),
        "credential submission or callback failed",
    )
    submitted.read()
    if urllib.parse.urlparse(submitted.geturl()).hostname != "identity-portal":
        final_url = urllib.parse.urlparse(submitted.geturl())
        safe_target = f"{final_url.hostname or 'unknown'}{final_url.path}"
        fail(f"callback did not return to Portal ({safe_target})")

    session = read_json(
        open_request(opener, f"{PORTAL_BASE}/api/auth/session", "session request failed"),
        "session response was invalid",
    )
    user = session.get("user")
    if not isinstance(user, dict) or not user.get("id"):
        fail("authenticated session was not established")

    me = open_request(opener, f"{PORTAL_BASE}/api/me", "authenticated /api/me failed")
    if me.status != 200:
        fail("authenticated /api/me was rejected")
    me_data = read_json(me, "/api/me response was invalid")
    if me_data.get("authenticated") is not True:
        fail("/api/me did not report an authenticated user")

    chat = open_request(opener, f"{PORTAL_BASE}/", "Chat page request failed")
    chat_page = chat.read().decode("utf-8", errors="replace")
    if chat.status != 200 or "JJDGuard Identity Lab" not in chat_page:
        fail("authenticated Chat page marker was missing")
    return me_data


def session_file() -> str:
    value = os.environ.get("IDENTITY_SESSION_FILE", "")
    if not value:
        return ""
    if not value.startswith("/state/") or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/."
        for char in value
    ):
        fail("session file path was invalid")
    return value


def current_session(opener) -> dict:
    session = read_json(
        open_request(opener, f"{PORTAL_BASE}/api/auth/session", "saved session request failed"),
        "saved session response was invalid",
    )
    user = session.get("user")
    if not isinstance(user, dict) or not user.get("id"):
        fail("saved Auth.js session was not authenticated")
    return user


def verify_authorization(opener) -> None:
    expected_models = os.environ.get("IDENTITY_EXPECT_MODELS", "")
    if expected_models:
        response = open_request(opener, f"{PORTAL_BASE}/api/models", "models request failed")
        payload = read_json(response, "models response was invalid")
        models = payload.get("models")
        if not isinstance(models, list):
            fail("models response lacked models")
        actual = sorted(
            model.get("id") for model in models
            if isinstance(model, dict) and isinstance(model.get("id"), str)
        )
        expected = sorted(model for model in expected_models.split(",") if model)
        if actual != expected:
            fail("models did not match latest authorization")

    denied_model = os.environ.get("IDENTITY_DENY_CHAT_MODEL", "")
    if denied_model:
        request = urllib.request.Request(
            f"{PORTAL_BASE}/api/chat",
            data=json.dumps({
                "model": denied_model,
                "messages": [{"role": "user", "content": "old department bypass"}],
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            opener.open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            if exc.code != 403:
                fail("old department model returned the wrong status")
        else:
            fail("old department model reached the proxy")

    expected_department = os.environ.get("IDENTITY_EXPECT_CHAT_DEPARTMENT", "")
    chat_model = os.environ.get("IDENTITY_CHAT_MODEL", "")
    if expected_department or chat_model:
        if not expected_department or not chat_model:
            fail("chat evidence configuration was incomplete")
        request = urllib.request.Request(
            f"{PORTAL_BASE}/api/chat",
            data=json.dumps({
                "model": chat_model,
                "messages": [{"role": "user", "content": "latest department evidence"}],
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        body = open_request(opener, request, "authorized chat request failed").read().decode("utf-8")
        marker = f"department={expected_department};model={chat_model}"
        if marker not in body:
            fail("portal-proxy did not observe the latest department header")


def main() -> None:
    provider = os.environ.get("IDENTITY_TEST_PROVIDER", "")
    username = os.environ.get("IDENTITY_TEST_USERNAME", "")
    password = os.environ.get("IDENTITY_TEST_PASSWORD", "")
    expected_email = os.environ.get("IDENTITY_EXPECT_EMAIL", "")
    reuse = os.environ.get("IDENTITY_REUSE_SESSION") == "1"
    path = session_file()
    if not reuse:
        if provider not in {"account-login", "enterprise-sso"}:
            fail("provider was invalid")
        if not username or not password:
            fail("credentials were not configured")
    elif not path:
        fail("saved session file was not configured")

    context = ssl.create_default_context(cafile="/certs/lab-ca.crt")
    jar = http.cookiejar.MozillaCookieJar(path) if path else http.cookiejar.CookieJar()
    if reuse:
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except (FileNotFoundError, OSError, http.cookiejar.LoadError):
            fail("saved Auth.js session could not be loaded")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )
    if reuse:
        user = current_session(opener)
    else:
        me = portal_sign_in(opener, provider, username, password)
        user = me.get("user", {})
        if path:
            jar.save(ignore_discard=True, ignore_expires=True)
            os.chmod(path, 0o600)
    if expected_email and user.get("email") != expected_email:
        fail("session represented the wrong email")
    verify_authorization(opener)
    if os.environ.get("IDENTITY_OUTPUT_USER_ID") == "1":
        user_id = user.get("id")
        if not isinstance(user_id, str) or not user_id or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in user_id
        ):
            fail("session user id was invalid")
        print(f"RESULT_USER_ID={user_id}")

    mode = "saved-session authorization" if reuse else f"{provider} callback"
    print(f"PASS: Portal {mode} established an authenticated Chat session")

if __name__ == "__main__":
    main()
