"""Real HTTP slow-body regression for shared Tier1/Judge transport reader."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import threading
import time
import urllib.request
import pytest
from app.detectors.http_budget import read_response_body


def test_slow_trickle_cannot_restart_response_deadline():
    stopped = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    if stopped.wait(.01):
                        break
            except OSError:
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        started = time.monotonic()
        with urllib.request.urlopen("http://127.0.0.1:" + str(server.server_port), timeout=.25) as response:
            with pytest.raises((TimeoutError, OSError)):
                read_response_body(response, 4096, started + .08)
        assert time.monotonic() - started < .35
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=1)


def test_body_reader_returns_only_one_byte_beyond_limit():
    assert read_response_body(io.BytesIO(b"abcdefgh"), 3, time.monotonic() + 1) == b"abcd"


def test_body_reader_rejects_expired_budget():
    with pytest.raises(TimeoutError):
        read_response_body(io.BytesIO(b"x"), 3, time.monotonic() - 1)


def test_body_reader_honors_parent_cancellation_before_read():
    from app.bounded_work import execution_budget
    canceled = threading.Event()
    canceled.set()
    response = io.BytesIO(b"sensitive")
    with execution_budget(time.monotonic() + 10, canceled):
        with pytest.raises(TimeoutError):
            read_response_body(response, 100, time.monotonic() + 10)
    assert response.tell() == 0
