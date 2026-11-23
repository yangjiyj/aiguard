"""Test-only transparent engine observation proxy. Records actual responses, not asserted verdicts.

Point an isolated gateway's security-engine URL here, and --upstream at its real engine.
Never install this observer in the customer production request path.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import hashlib
import json
import os
from pathlib import Path
import threading

from bench.e2e_bench import canonical, digest, evaluate, http_post, finding_matches_scope
from app.header_compat import resolve_raw_headers


def observation(request, response, stage, status, *, run_id, runtime_revision, key, canaries=()):
    # Derive completion and detection from the actual engine HTTP response.
    row = {"id": "observed", "label": 0, "stage": stage,
           "checks": ["semantic", "dlp"] if stage == "input" else ["dlp"]}
    outcome = evaluate(row, "engine", status, response, request_id=request.get("request_id", ""))
    data = {"producer": "engine-observation-proxy-v1", "run_id": run_id,
            "request_id": request.get("request_id", ""), "stage": stage,
            "coverage": outcome["coverage"], "detected": outcome["detected"],
            "signals": [{"type": f.get("type", ""), "category": f.get("category", "")}
                        for f in response.get("findings", []) if finding_matches_scope(f, row)],
            "runtime_revision": response.get("semantic_config_revision") or runtime_revision,
            "canary_hashes_seen": [digest(c.encode()) for c in canaries
                                   if stage == "output" and c and c in str(request.get("content", ""))],
            "engine_request_sha256": digest(canonical(request)),
            "engine_response_sha256": digest(canonical(response))}
    data["signature"] = hmac.new(key, canonical(data), hashlib.sha256).hexdigest()
    return data


def observer_server(address, *, upstream, receipts, run_id, runtime_revision, key, timeout=30, canaries=()):
    if not key:
        raise ValueError("observer signing key must come from an environment variable")
    write_lock = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # never log bodies, paths, credentials, or free-form upstream errors
        def do_POST(self):
            if self.path not in {"/check-input/", "/check-input/batch", "/check-output/"}:
                self.send_error(404); return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4 * 1024 * 1024:
                    self.send_error(413); return
                request = json.loads(self.rfile.read(length))
            except (ValueError, OSError):
                self.send_error(400); return
            token, conflict = resolve_raw_headers((k.encode(), v.encode("latin-1")) for k, v in self.headers.raw_items())
            if conflict:
                self.send_error(401); return
            headers = {"X-JJDGuard-Internal-Token": token} if token else {}
            status, response_headers, body, error = http_post(upstream.rstrip("/") + self.path, request, headers, timeout)
            if not status:
                status, body = 502, '{"error":{"code":"observation_upstream_failure"}}'
            try:
                response = json.loads(body)
                requests = request if isinstance(request, list) else [request]
                responses = response if isinstance(response, list) else [response]
                # Never zip-drop missing or mismatched results into a successful receipt.
                if len(requests) == len(responses):
                    records = []
                    for req, resp in zip(requests, responses):
                        if isinstance(req, dict) and isinstance(resp, dict):
                            records.append(observation(req, resp, "output" if "check-output" in self.path else "input", status,
                                run_id=run_id, runtime_revision=runtime_revision, key=key, canaries=canaries))
                    with write_lock:
                        with Path(receipts).open("a", encoding="utf-8") as stream:
                            for record in records:
                                stream.write(json.dumps(record, ensure_ascii=True) + "\n")
                            stream.flush()
            except (ValueError, OSError):
                pass  # absent observations deliberately remain unknown in the runner
            encoded = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    return ThreadingHTTPServer(address, Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--port", type=int, default=19099)
    parser.add_argument("--receipts", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--runtime-revision", required=True)
    parser.add_argument("--key-env", default="JJD_BENCH_RECEIPT_KEY")
    parser.add_argument("--dataset", help="Frozen synthetic dataset; required to attest output canary attempts")
    args = parser.parse_args(argv)
    canaries = []
    if args.dataset:
        canaries = [json.loads(line).get("canary", "") for line in Path(args.dataset).read_text().splitlines() if line.strip()]
    server = observer_server(("127.0.0.1", args.port), upstream=args.upstream, receipts=args.receipts,
                run_id=args.run_id, runtime_revision=args.runtime_revision, key=os.getenv(args.key_env, "").encode(), canaries=canaries)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
