import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HITS = []


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            return self._send(200, {"object": "list", "data": [{"id": "mock-model", "object": "model"}]})
        if self.path == "/hits":
            return self._send(200, {"hits": len(HITS)})
        self._send(200, {"ok": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n) if n else b""
        HITS.append(len(body))
        self._send(200, {
            "id": "chatcmpl-mock", "object": "chat.completion", "created": 0, "model": "mock-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "mock reply"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        })

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
