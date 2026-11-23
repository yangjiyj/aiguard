#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("identity-lab-control-plane-api.py")
SPEC = importlib.util.spec_from_file_location("identity_lab_control_plane_api", MODULE_PATH)
assert SPEC and SPEC.loader
control_api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control_api)


class SafeErrorCodeTest(unittest.TestCase):
    def test_returns_only_allowlisted_error_code(self) -> None:
        marker = "NeverEchoControlPlaneSecret-42"
        payload = json.dumps({
            "error": {"code": "directory_publish_failed", "message": marker},
            "request": marker,
        }).encode()
        self.assertEqual(control_api.safe_error_code(payload), "directory_publish_failed")
        self.assertNotIn(marker, control_api.safe_error_code(payload))

    def test_rejects_malformed_or_untrusted_codes(self) -> None:
        for payload in (b"", b"not-json", b'{"error":{"code":"BAD/value"}}'):
            self.assertEqual(control_api.safe_error_code(payload), "unknown")


if __name__ == "__main__":
    unittest.main()
