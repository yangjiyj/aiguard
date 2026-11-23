#!/usr/bin/env python3
"""Contract tests for the controlled Streamable HTTP MCP server."""
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import threading
import unittest

path = pathlib.Path(__file__).with_name("mock_mcp_server.py")
spec = importlib.util.spec_from_file_location("mock_mcp_server", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MockMCPServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({
            "MCP_E2E_UPSTREAM_TOKEN": "upstream-only-secret",
            "MCP_E2E_CALLER_TOKEN": "caller-data-plane-secret",
            "MCP_E2E_CONTROL_TOKEN": "control-only-secret",
        })
        cls.state = module.ServerState.from_environment("primary")
        cls.server = module.ThreadingHTTPServer(
            ("127.0.0.1", 0), module.make_handler(cls.state))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        payload = None if body is None else json.dumps(body).encode()
        headers = dict(headers or {})
        if payload is not None:
            headers.setdefault("Content-Type", "application/json")
        conn.request(method, path, payload, headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def control(self, body):
        return self.request("POST", "/__control", body, {
            "X-E2E-Control-Token": "control-only-secret"})

    def rpc(self, body, session="", auth="upstream-only-secret"):
        headers = {"Authorization": "Bearer " + auth,
                   "Accept": "application/json, text/event-stream"}
        if session:
            headers.update({"Mcp-Session-Id": session,
                            "MCP-Protocol-Version": "2025-11-25"})
        return self.request("POST", "/mcp", body, headers)

    def initialize(self):
        status, headers, raw = self.rpc({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}}})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["result"]["protocolVersion"], "2025-11-25")
        return headers.get("Mcp-Session-Id") or headers.get("MCP-Session-Id")

    def setUp(self):
        self.control({"mode": "clean", "reset": True})

    def test_session_tools_and_redacted_state(self):
        session = self.initialize()
        status, _, raw = self.rpc(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            session)
        self.assertEqual([x["name"] for x in json.loads(raw)["result"]["tools"]],
                         ["echo", "dangerous_exec"])
        args = {"text": "hello", "password": "do-not-retain"}
        status, _, raw = self.rpc({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "echo", "arguments": args}}, session)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["result"]["content"][0]["text"], "hello")
        _, _, raw = self.request("GET", "/__state", headers={
            "X-E2E-Control-Token": "control-only-secret"})
        state = json.loads(raw)
        self.assertEqual(state["counts"]["correct_auth"], 3)
        self.assertNotIn("do-not-retain", json.dumps(state))
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(state["recent_calls"][0]["arguments_sha256"],
                         hashlib.sha256(canonical).hexdigest())

    def test_batch_protocol_and_auth_rejections(self):
        status, _, raw = self.rpc([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}])
        self.assertEqual(status, 400)
        self.assertIn("batch", json.loads(raw)["error"]["message"].lower())
        status, _, raw = self.rpc({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(status, 400)
        status, _, _ = self.rpc({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"}},
            auth="caller-data-plane-secret")
        self.assertEqual(status, 401)
        _, _, raw = self.request("GET", "/__state", headers={
            "X-E2E-Control-Token": "control-only-secret"})
        text = raw.decode()
        self.assertEqual(json.loads(raw)["counts"]["caller_auth_forwarded"], 1)
        for secret in ("upstream-only-secret", "caller-data-plane-secret",
                       "control-only-secret"):
            self.assertNotIn(secret, text)

    def test_mode_fixtures_and_capacity(self):
        for mode, marker in (("poison", "ignore all previous"),
                             ("rug_pull", "changed after approval"),
                             ("shadow", "shadow-only")):
            self.control({"mode": mode})
            session = self.initialize()
            _, _, raw = self.rpc(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                session)
            self.assertIn(marker, raw.decode().lower())
        self.control({"mode": "huge"})
        session = self.initialize()
        _, _, raw = self.rpc({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "x"}}}, session)
        self.assertGreater(len(raw), 8 << 20)


if __name__ == "__main__":
    unittest.main()
