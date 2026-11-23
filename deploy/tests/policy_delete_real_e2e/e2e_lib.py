"""Helpers for the isolated policy-delete e2e stack (stdlib only).

Everything is configured through the environment that run.sh exports:
  E2E_ENV_FILE  secrets file of the stack (KEY=VALUE lines, also holds ADMIN_PASSWORD / API_KEY once set up)
  E2E_PROJECT   docker compose project name (used for `docker exec` into postgres / the mock upstream)
  E2E_CP_PORT / E2E_GW_PORT   loopback ports of control-plane and gateway-core
"""
import base64
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

ENV_FILE = os.environ["E2E_ENV_FILE"]
PROJECT = os.environ["E2E_PROJECT"]
CP = f"http://127.0.0.1:{os.environ['E2E_CP_PORT']}"
GW = f"http://127.0.0.1:{os.environ['E2E_GW_PORT']}"


def env(name, default=None):
    with open(ENV_FILE, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith(name + "="):
                return line.rstrip("\n").split("=", 1)[1]
    if default is not None:
        return default
    raise KeyError(name)


def set_env(name, value):
    with open(ENV_FILE, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def req(method, url, body=None, token=None, headers=None, timeout=30):
    data = None
    h = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = "Bearer " + token
    if headers:
        h.update(headers)
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        status = e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw


def captcha_login(username, password):
    _, ch = req("GET", CP + "/admin/v1/captcha")
    svg = base64.b64decode(ch["image"].split("base64,", 1)[1]).decode()
    code = "".join(re.findall(r"<text[^>]*>([^<]+)</text>", svg)).strip()
    status, body = req("POST", CP + "/admin/v1/login",
                       {"username": username, "password": password, "captcha_id": ch["captcha_id"], "captcha_code": code})
    if status != 200 or "token" not in (body or {}):
        raise RuntimeError(f"login failed {status} {body}")
    return body["token"], body


def admin_token():
    """Log in as admin; the first login after bootstrap must change the bootstrap password."""
    new_pw = env("ADMIN_PASSWORD", "")
    if new_pw:
        try:
            return captcha_login("admin", new_pw)[0]
        except RuntimeError:
            pass
    token, body = captcha_login("admin", env("BOOTSTRAP_ADMIN_PASSWORD"))
    if body["user"].get("password_change_required"):
        new_pw = new_pw or "Delbtn#E2e-Changed-20261109"
        status, resp = req("POST", CP + "/admin/v1/me/change-password",
                           {"current_password": env("BOOTSTRAP_ADMIN_PASSWORD"), "new_password": new_pw}, token=token)
        if status not in (200, 204):
            raise RuntimeError(f"change password failed {status} {resp}")
        set_env("ADMIN_PASSWORD", new_pw)
        return captcha_login("admin", new_pw)[0]
    return token


def psql(sql):
    out = subprocess.run(
        ["docker", "exec", "-e", "PGPASSWORD=" + env("POSTGRES_PASSWORD"), PROJECT + "-postgres-1",
         "psql", "-U", "jjdguard", "-d", "jjdguard", "-At", "-F", "|", "-c", sql],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    return out.stdout.strip()


def wait_for(fn, timeout=90, interval=2, what="condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {what}; last={last!r}")
