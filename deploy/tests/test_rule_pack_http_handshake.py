"""部署契约：默认 HTTP 客户端完成两次带 attestation 的规则包握手。

握手在独立 Python 进程和受控本机 HTTPServer 内执行，覆盖生产默认 client
factory、真实请求头、持有版本及第二次实际计数回执，同时避免污染其它 deploy
测试使用的 ``app`` 包。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

HANDSHAKE_SCRIPT = r"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

socket.gethostname = lambda: "  deploy-node  "

from app.rule_pack_loader import (
    NODE_HEADER,
    RULEPACK_ACTIVE_COUNT_HEADER,
    RULEPACK_ATTESTATION_HEADER,
    RULEPACK_REFRESH_SECONDS_HEADER,
    RULEPACK_SKIPPED_COUNT_HEADER,
    RULEPACK_VERSION_HEADER,
    RulePackConfig,
    RulePackLoader,
)

ATTESTATION = "deploy-attestation-secret"
seen = {"requests": []}


class Engine:
    def load_custom_rules(self, rules):
        self.custom_rules = SimpleNamespace(active_rules=[])

    def load_content_audit_exceptions(self, exceptions):
        pass

    def load_file_policy(self, policy):
        self.file_policy = policy


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        seen["requests"].append(
            {
                "path": self.path,
                "node_id": self.headers.get(NODE_HEADER, ""),
                "refresh_seconds": self.headers.get(
                    RULEPACK_REFRESH_SECONDS_HEADER, ""
                ),
                "held_version": self.headers.get(RULEPACK_VERSION_HEADER, ""),
                "active_count": self.headers.get(RULEPACK_ACTIVE_COUNT_HEADER),
                "skipped_count": self.headers.get(RULEPACK_SKIPPED_COUNT_HEADER),
                # 只输出比较结果，绝不把专用 token 写进测试日志。
                "attestation_ok": self.headers.get(RULEPACK_ATTESTATION_HEADER)
                == ATTESTATION,
            }
        )
        body = json.dumps(
            {
                "tenant_id": "tenant_default",
                "version": "deploy-handshake-v1",
                "rules": [],
                "exceptions": [],
                "skipped": [],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


server = HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    config = RulePackConfig(
        base_url=f"http://127.0.0.1:{server.server_port}",
        token="",
        node_id="   ",
        refresh_seconds=999999,
    )
    config.attestation_token = ATTESTATION
    loader = RulePackLoader(config)
    engine = Engine()
    assert loader.refresh_once(engine) is True
    assert loader.refresh_once(engine) is True
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)

print(json.dumps(seen))
"""


def test_default_http_two_pull_handshake_sends_attestation_and_telemetry():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "apps" / "security-engine")
    result = subprocess.run(
        [sys.executable, "-c", HANDSHAKE_SCRIPT],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout.strip().splitlines()[-1])
    assert seen["requests"] == [
        {
            "path": "/admin/v1/internal/rules/pack",
            "node_id": "security-engine:deploy-node",
            "refresh_seconds": "3600",
            "held_version": "",
            "active_count": None,
            "skipped_count": None,
            "attestation_ok": True,
        },
        {
            "path": "/admin/v1/internal/rules/pack",
            "node_id": "security-engine:deploy-node",
            "refresh_seconds": "3600",
            "held_version": "deploy-handshake-v1",
            "active_count": "0",
            "skipped_count": "0",
            "attestation_ok": True,
        },
    ]
