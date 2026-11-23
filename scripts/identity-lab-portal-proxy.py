#!/usr/bin/env python3
"""Minimal authenticated portal-proxy used only by the identity lab."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TOKEN = os.environ["PORTAL_INTERNAL_TOKEN"]
MAX_REQUEST_BODY_BYTES = 64 * 1024
MODELS = [
    {"id": "lab-research-model", "displayName": "Lab Research Model"},
    {"id": "lab-marketing-model", "displayName": "Lab Marketing Model"},
]
DEPARTMENT_MODELS = {
    "lab-research": "lab-research-model",
    "lab-marketing": "lab-marketing-model",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "identity-lab-portal-proxy"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.write_json(401, {"error": "unauthorized"})
            return False
        return True

    def evidence(self, model: str = "") -> tuple[str, str]:
        department = self.headers.get("X-Portal-Direct-Department", "")
        print(
            json.dumps(
                {"path": self.path, "department": department, "model": model},
                separators=(",", ":"),
            ),
            flush=True,
        )
        return department, model

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json(200, {"status": "ok"})
            return
        if self.path != "/v1/models":
            self.write_json(404, {"error": "not_found"})
            return
        if not self.authorized():
            return
        department, _ = self.evidence()
        default_model = DEPARTMENT_MODELS.get(department)
        self.write_json(200, {"models": MODELS, "defaultModelId": default_model})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.write_json(404, {"error": "not_found"})
            return
        if not self.authorized():
            return
        try:
            raw_length = self.headers.get("Content-Length", "0")
            length = int(raw_length)
        except (TypeError, ValueError):
            self.write_json(400, {"error": "invalid_request"})
            return
        if length < 0:
            self.write_json(400, {"error": "invalid_request"})
            return
        if length > MAX_REQUEST_BODY_BYTES:
            self.write_json(413, {"error": "request_too_large"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            model = payload["model"]
            if not isinstance(model, str):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.write_json(400, {"error": "invalid_request"})
            return
        department, _ = self.evidence(model)
        if DEPARTMENT_MODELS.get(department) != model:
            self.write_json(403, {"error": "department_model_mismatch"})
            return
        content = f"department={department};model={model}"
        frame = (
            "data: "
            + json.dumps({"choices": [{"delta": {"content": content}}]}, separators=(",", ":"))
            + "\n\ndata: [DONE]\n\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(frame)))
        self.end_headers()
        self.wfile.write(frame)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8788), Handler).serve_forever()
