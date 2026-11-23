#!/usr/bin/env python3
import json
import os
import re
import sys
import urllib.error
import urllib.request

BASE_URL = "http://control-plane:8081"
SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_]+$")


def safe_error_code(payload: bytes) -> str:
    try:
        code = json.loads(payload).get("error", {}).get("code", "")
    except Exception:
        return "unknown"
    if isinstance(code, str) and SAFE_ERROR_CODE.fullmatch(code):
        return code
    return "unknown"


def main() -> int:
    method = os.environ.get("CONTROL_API_METHOD", "").strip().upper()
    path = os.environ.get("CONTROL_API_PATH", "").strip()
    body = os.environ.get("CONTROL_API_BODY", "")
    token = os.environ.get("CONTROL_API_TOKEN", "")

    if method not in {"GET", "POST", "PUT"} or not path.startswith("/admin/v1/") or "://" in path:
        print("control-plane API request rejected", file=sys.stderr)
        return 2

    data = body.encode("utf-8") if body else None
    request = urllib.request.Request(BASE_URL + path, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        code = safe_error_code(exc.read(64 * 1024))
        print(
            f"control-plane API request failed status={exc.code} path={path} code={code}",
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(f"control-plane API request unavailable path={path}", file=sys.stderr)
        return 1

    try:
        json.loads(payload)
    except Exception:
        print(f"control-plane API returned invalid JSON path={path}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
