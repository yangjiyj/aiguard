#!/usr/bin/env python3
"""A loopback-only, prompt-free OpenAI-compatible acceptance fixture."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import sys
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


HOST = "127.0.0.1"
MAX_BODY_BYTES = 64 * 1024
MODEL_ID = "offline-fixture"


class AuditLog:
    """Append bounded request metadata without retaining request content."""

    def __init__(self, path: pathlib.Path | None) -> None:
        self._lock = threading.Lock()
        self._parent_parts: tuple[str, ...] = ()
        self._name: str | None = None
        self._identity: tuple[int, int] | None = None
        if path is None:
            return
        self._require_secure_openat()
        self._parent_parts, self._name = self._path_parts(path)
        try:
            parent_fd = self._open_parent()
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        try:
            self._identity = self._initialize_sink(parent_fd)
        finally:
            os.close(parent_fd)

    @staticmethod
    def _require_secure_openat() -> None:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise ValueError("platform lacks required O_NOFOLLOW/O_DIRECTORY support")

    @staticmethod
    def _path_parts(path: pathlib.Path) -> tuple[tuple[str, ...], str]:
        absolute = path if path.is_absolute() else pathlib.Path.cwd() / path
        parts = absolute.parts
        if not parts or parts[0] != os.sep:
            raise ValueError("audit path must be absolute after normalization")
        components = parts[1:]
        if not components or any(part in {"", ".", ".."} for part in components):
            raise ValueError("audit path is not canonical")
        return tuple(components[:-1]), components[-1]

    def _open_parent(self) -> int:
        try:
            directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise RuntimeError(f"audit root cannot be opened safely: {error}") from error
        try:
            for part in self._parent_parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return directory_fd
        except OSError as error:
            os.close(directory_fd)
            raise RuntimeError(f"audit parent cannot be opened safely: {error}") from error

    @staticmethod
    def _same_file(left: os.stat_result, right: tuple[int, int]) -> bool:
        return (left.st_dev, left.st_ino) == right

    def _initialize_sink(self, parent_fd: int) -> tuple[int, int]:
        assert self._name is not None
        listed: os.stat_result | None = None
        try:
            listed = os.stat(self._name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK | os.O_NOFOLLOW
            try:
                descriptor = os.open(self._name, flags, 0o600, dir_fd=parent_fd)
            except OSError as error:
                raise ValueError(f"audit log cannot be created safely: {error}") from error
        except OSError as error:
            raise ValueError(f"audit path is unavailable: {error}") from error
        else:
            if not stat.S_ISREG(listed.st_mode):
                raise ValueError("audit path is not a regular non-symlink file")
            flags = os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | os.O_NOFOLLOW
            try:
                descriptor = os.open(self._name, flags, dir_fd=parent_fd)
            except OSError as error:
                raise ValueError(f"audit log cannot be opened safely: {error}") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("audit path is not a regular non-symlink file")
            if listed is not None and not self._same_file(metadata, (listed.st_dev, listed.st_ino)):
                raise ValueError("audit path changed while it was opened")
            return metadata.st_dev, metadata.st_ino
        finally:
            os.close(descriptor)

    def _open_current_sink(self, parent_fd: int) -> int:
        assert self._name is not None and self._identity is not None
        try:
            listed = os.stat(self._name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            raise RuntimeError(f"audit path is unavailable: {error}") from error
        if not stat.S_ISREG(listed.st_mode) or not self._same_file(listed, self._identity):
            raise RuntimeError("audit path was replaced or is not a regular non-symlink file")
        flags = os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | os.O_NOFOLLOW
        try:
            descriptor = os.open(self._name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise RuntimeError(f"audit log cannot be opened safely: {error}") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or not self._same_file(metadata, self._identity):
                raise RuntimeError("audit path changed while it was opened")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def write(self, method: str, route: str, request_bytes: int, status: int, stream: bool) -> None:
        if self._name is None:
            return
        entry = {
            "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": method,
            "path": route,
            "request_bytes": request_bytes,
            "status": status,
            "stream": stream,
        }
        encoded = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            parent_fd: int | None = None
            descriptor: int | None = None
            try:
                parent_fd = self._open_parent()
                descriptor = self._open_current_sink(parent_fd)
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise RuntimeError("audit log write was incomplete")
                    view = view[written:]
                os.fsync(descriptor)
            except OSError as error:
                raise RuntimeError(f"audit log cannot be written safely: {error}") from error
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if parent_fd is not None:
                    os.close(parent_fd)


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], audit: AuditLog) -> None:
        super().__init__(address, FixtureHandler)
        self.audit = audit


class FixtureHandler(BaseHTTPRequestHandler):
    server: FixtureServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # BaseHTTPRequestHandler logs request lines; keep request handling quiet
        # so malformed data or query strings cannot reach process logs.
        return

    def _audit_route(self) -> str:
        if self.path == "/v1/models":
            return "/v1/models"
        if self.path == "/v1/chat/completions":
            return "/v1/chat/completions"
        return "unknown"

    def _audit(self, status: int, request_bytes: int, stream: bool = False) -> bool:
        try:
            self.server.audit.write(self.command, self._audit_route(), request_bytes, status, stream)
        except RuntimeError:
            # An unavailable audit sink is fail-closed for this fixture.
            self.close_connection = True
            return False
        return True

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any], request_bytes: int) -> None:
        if not self._audit(status, request_bytes):
            return
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error_json(self, status: HTTPStatus, request_bytes: int) -> None:
        self._send_json(status, {"error": {"code": status.value, "message": status.phrase}}, request_bytes)

    def _read_json_body(self) -> tuple[dict[str, Any] | None, int, HTTPStatus | None]:
        if self.headers.get("Transfer-Encoding"):
            return None, 0, HTTPStatus.BAD_REQUEST
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return None, 0, HTTPStatus.LENGTH_REQUIRED
        try:
            length = int(raw_length)
        except ValueError:
            return None, 0, HTTPStatus.BAD_REQUEST
        if length < 0:
            return None, 0, HTTPStatus.BAD_REQUEST
        if length > MAX_BODY_BYTES:
            return None, length, HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        body = self.rfile.read(length)
        if len(body) != length:
            return None, len(body), HTTPStatus.BAD_REQUEST
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, length, HTTPStatus.BAD_REQUEST
        if not isinstance(value, dict):
            return None, length, HTTPStatus.BAD_REQUEST
        return value, length, None

    @staticmethod
    def _valid_chat_request(value: dict[str, Any]) -> bool:
        return isinstance(value.get("model"), str) and isinstance(value.get("messages"), list)

    def do_GET(self) -> None:
        if self.path != "/v1/models":
            self._send_error_json(HTTPStatus.NOT_FOUND, 0)
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "object": "list",
                "data": [{"id": MODEL_ID, "object": "model", "created": 0, "owned_by": "offline"}],
            },
            0,
        )

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED if self.path == "/v1/models" else HTTPStatus.NOT_FOUND, 0)
            return
        value, request_bytes, error = self._read_json_body()
        if error is not None:
            self._send_error_json(error, request_bytes)
            return
        assert value is not None
        if not self._valid_chat_request(value):
            self._send_error_json(HTTPStatus.BAD_REQUEST, request_bytes)
            return
        if value.get("stream") is True:
            self._send_stream(request_bytes)
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "id": "chatcmpl-offline-fixture",
                "object": "chat.completion",
                "created": 0,
                "model": MODEL_ID,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "offline fixture response"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
            request_bytes,
        )

    def _send_stream(self, request_bytes: int) -> None:
        events = [
            {
                "id": "chatcmpl-offline-fixture",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": MODEL_ID,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": "offline fixture response"}, "finish_reason": None}],
            },
            {
                "id": "chatcmpl-offline-fixture",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": MODEL_ID,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            },
        ]
        payload = b"".join(
            [b"data: " + json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n\n" for event in events]
        ) + b"data: [DONE]\n\n"
        if not self._audit(HTTPStatus.OK, request_bytes, stream=True):
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_PUT(self) -> None:
        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, 0)

    def do_DELETE(self) -> None:
        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, 0)

    def do_PATCH(self) -> None:
        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--audit-log", type=pathlib.Path)
    args = parser.parse_args()
    if args.host != HOST:
        parser.error("only 127.0.0.1 is permitted")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    return args


def main() -> int:
    args = parse_args()
    try:
        audit = AuditLog(args.audit_log)
        server = FixtureServer((args.host, args.port), audit)
    except (OSError, ValueError) as error:
        print(f"[error] offline upstream rejected: {error}", file=sys.stderr)
        return 2
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
