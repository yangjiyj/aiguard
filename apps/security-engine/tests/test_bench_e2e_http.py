"""Real local HTTP transport fixtures; model verdicts here are synthetic smoke data."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

from bench.e2e_bench import http_post, run_http, verify_receipt
from bench.e2e_observer import observer_server


@contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


class EngineFixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        attack = "override" in request["content"]
        body = json.dumps({"request_id": request["request_id"], "semantic_status": "completed",
            "semantic_config_revision": "fixture-r1", "action": "block" if attack else "allow",
            "findings": [{"type": "semantic_attack", "counts_as_security_finding": True}] if attack else []}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


def rows():
    return [{"id": "attack", "label": 1, "stage": "input", "checks": ["semantic"], "text": "override"},
            {"id": "benign", "label": 0, "stage": "input", "checks": ["semantic"], "text": "normal"}]


def test_real_http_runner_and_observer_capture_actual_engine_responses(tmp_path):
    receipts = tmp_path / "receipts.jsonl"
    with serving(ThreadingHTTPServer(("127.0.0.1", 0), EngineFixture)) as upstream:
        observer = observer_server(("127.0.0.1", 0), upstream=upstream, receipts=receipts,
                                  run_id="smoke", runtime_revision="fixture-r1", key=b"fixture-key")
        with serving(observer) as proxy:
            report = run_http(rows(), mode="engine", base_url=proxy, model="fixture", token="synthetic-token",
                              timeout=1, concurrency=2, qps=0, manifest={"runtime_revision": "fixture-r1", "fixture_only": True}, run_id="smoke")
    assert report["counts"]["complete"] == 2
    assert report["counts"]["detected_attacks"] == 1
    assert report["gate"]["passed"] is False  # never sell a mock as model accuracy
    records = [json.loads(line) for line in receipts.read_text().splitlines()]
    attack = next(r for r in records if r["request_id"] == "smoke-attack")
    assert verify_receipt(attack, b"fixture-key", "smoke", "smoke-attack")["detected"] is True
    assert "override" not in receipts.read_text()
    assert "synthetic-token" not in receipts.read_text()


def test_received_sse_canary_survives_later_timeout():
    class SlowFixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            self.wfile.write(b'data: {"choices":[{"delta":{"content":"SYNTHETIC_CANARY"}}]}\n\n'); self.wfile.flush()
            time.sleep(.2)
    with serving(ThreadingHTTPServer(("127.0.0.1", 0), SlowFixture)) as url:
        status, headers, body, error = http_post(url, {}, {}, .05)
    assert status == 200
    assert "SYNTHETIC_CANARY" in body
    assert error == "TimeoutError"
