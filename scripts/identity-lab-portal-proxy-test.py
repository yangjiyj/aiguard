#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("PORTAL_INTERNAL_TOKEN", "portal-proxy-test-token")
SPEC = importlib.util.spec_from_file_location(
    "identity_lab_portal_proxy",
    ROOT / "scripts" / "identity-lab-portal-proxy.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class RejectRead:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, _length: int = -1) -> bytes:
        self.calls += 1
        raise AssertionError("request body must not be read")


class PortalProxyContentLengthTest(unittest.TestCase):
    def invoke(self, content_length: str) -> tuple[int, int]:
        handler = object.__new__(MODULE.Handler)
        handler.path = "/v1/chat/completions"
        handler.headers = {
            "Authorization": "Bearer portal-proxy-test-token",
            "Content-Length": content_length,
        }
        handler.rfile = RejectRead()
        response: list[int] = []
        handler.authorized = lambda: True
        handler.write_json = lambda status, _payload: response.append(status)

        handler.do_POST()

        self.assertEqual(len(response), 1)
        return response[0], handler.rfile.calls

    def test_rejects_invalid_negative_and_oversized_lengths_before_read(self) -> None:
        cases = (("invalid", 400), ("-1", 400), ("65537", 413))
        for content_length, expected_status in cases:
            with self.subTest(content_length=content_length):
                status, read_calls = self.invoke(content_length)
                self.assertEqual(status, expected_status)
                self.assertEqual(read_calls, 0)


if __name__ == "__main__":
    unittest.main()
