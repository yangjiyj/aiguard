"""Synthetic acceptance through the running HTTP server, with no policy changes."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


def run(base_url="http://127.0.0.1:8000", fixtures=Path("/app/file-fixtures")):
    token = os.environ.get("JJD_INTERNAL_API_SECRET", "")
    headers = {"X-JJDGuard-Internal-Token": token}
    def request(path, body=None, method="GET", content_type="application/json"):
        req = urllib.request.Request(base_url + path, data=body, method=method,
                                     headers=dict(headers, **{"Content-Type": content_type}))
        with urllib.request.urlopen(req, timeout=40) as response:
            return json.loads(response.read())
    ready = request("/ready")
    if not ready["ready"] or not ready["file_content_dlp"]["enabled"] or not ready["scan_store"]["available"]:
        raise RuntimeError("HTTP file capabilities are not ready")
    tenant = "synthetic-release-" + uuid.uuid4().hex
    cases = []
    for name in ("chinese-phone.pdf", "chinese-phone.png", "scanned-chinese-phone.pdf"):
        data = (fixtures / name).read_bytes()
        for stage in ("input", "output"):
            body = {"request_id": tenant + "-" + stage, "content": "普通业务说明", "skip_semantic": True,
                    "context": {"attachments": [{"file_name": name, "content_type": "image/png" if name.endswith(".png") else "application/pdf",
                                                 "data_base64": base64.b64encode(data).decode()}]}}
            result = request("/check-" + stage + "/", json.dumps(body).encode(), "POST")
            findings = result.get("raw_findings", [])
            incomplete = result.get("inspection_status") != "completed" or any(
                f.get("category", "").startswith("file_content_") or f.get("type") in ("engine_runtime", "semantic_telemetry") for f in findings)
            detected = any(f.get("category") == "phone_cn" and f.get("content_source") == "file_attachment" for f in findings)
            cases.append({"fixture": name, "stage": stage, "action": result.get("action"),
                          "coverage_complete": not incomplete, "passed": detected and not incomplete and result.get("action") in ("block", "audit")})
    data = b"synthetic temporary scan object"
    query = urllib.parse.urlencode({"tenant_id": tenant, "request_id": tenant, "file_name": "release-probe.txt"})
    obj = request("/scan-objects?" + query, data, "PUT", "application/octet-stream")
    obj_path = "/scan-objects/" + urllib.parse.quote(obj["object_id"], safe="")
    isolated = False
    try:
        try:
            request(obj_path + "?tenant_id=synthetic-wrong-tenant", method="DELETE")
        except urllib.error.HTTPError as exc:
            isolated = exc.code == 404
    finally:
        request(obj_path + "?" + query, method="DELETE")
    store_ok = obj["sha256"] == hashlib.sha256(data).hexdigest() and obj["size"] == len(data) and isolated
    passed = all(c["passed"] for c in cases) and store_ok
    return {"passed": passed, "readiness": ready, "cases": cases,
            "scan_store_roundtrip": store_ok, "cross_tenant_delete_rejected": isolated}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--fixtures", type=Path, default=Path("/app/file-fixtures"))
    args = parser.parse_args()
    result = run(args.base_url, args.fixtures)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
