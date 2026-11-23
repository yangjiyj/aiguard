"""
API 接口测试
"""

import anyio
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

import app.api.check_input as check_input_module
import app.api.check_output as check_output_module
import app.api.test_security as test_security_module
import app.main as main_module
from app.header_compat import resolve_raw_headers


INTERNAL_HEADER = "X-JJDGuard-Internal-Token"


def _run(coro):
    return anyio.run(lambda: coro)


def _request(path: str, headers: dict[str, str] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in (headers or {}).items()
            ],
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
        }
    )


async def _ok_response(_: Request) -> Response:
    return Response(status_code=200)


@pytest.fixture(autouse=True)
def _default_enforcing_engine():
    old = main_module.engine.audit_only
    main_module.engine.audit_only = False
    yield
    main_module.engine.audit_only = old


def test_openapi_uses_jjdguard_product_name():
    assert main_module.app.title == "JJDGuard Security Engine"
    assert "JJDGuard" in main_module.__doc__


class TestHealthCheck:
    def test_health_endpoint(self):
        """测试健康检查端点"""
        response = _run(main_module.health_check())
        assert response["status"] == "healthy"


class TestInternalAuth:
    def test_check_input_allows_without_secret_for_dev_compatibility(self, monkeypatch):
        monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)

        response = _run(
            main_module.require_internal_token(
                _request("/check-input/"),
                _ok_response,
            )
        )

        assert response.status_code == 200

    def test_protected_endpoint_requires_internal_secret_when_configured(self, monkeypatch):
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret-token")

        response = _run(
            main_module.require_internal_token(
                _request("/check-input/"),
                _ok_response,
            )
        )

        assert response.status_code == 401

    def test_protected_endpoint_accepts_matching_internal_secret(self, monkeypatch):
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret-token")

        response = _run(
            main_module.require_internal_token(
                _request("/check-input/", {INTERNAL_HEADER: "secret-token"}),
                _ok_response,
            )
        )

        assert response.status_code == 200

    def test_health_remains_public_when_secret_configured(self, monkeypatch):
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret-token")

        response = _run(
            main_module.require_internal_token(
                _request("/health"),
                _ok_response,
            )
        )

        assert response.status_code == 200

    def test_openapi_requires_internal_secret_when_configured(self, monkeypatch):
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret-token")

        response = _run(
            main_module.require_internal_token(
                _request("/openapi.json"),
                _ok_response,
            )
        )

        assert response.status_code == 401


class TestCheckInput:
    def test_check_input_without_trailing_slash_does_not_redirect(self):
        with TestClient(main_module.app) as client:
            response = client.post(
                "/check-input",
                json={"request_id": "no-slash", "content": "hello"},
            )

        assert response.status_code == 200
        assert not response.history

    def test_check_input_empty(self):
        """测试空输入检查"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(request_id="test_001", content="")
        ))
        assert response.action == "allow"

    def test_check_input_with_pii(self):
        """测试带 PII 的输入"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_002",
                content="手机号: 13812345678",
            )
        ))
        assert len(response.findings) > 0

    def test_check_input_with_secret(self):
        """测试带密钥的输入"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_003",
                content="AWS_KEY=AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret nosemgrep
            )
        ))
        assert response.action == "audit"

    def test_check_input_with_ai_ide_github_token(self):
        """测试 AI 编程工具流量中的 GitHub Token 外发"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_ai_ide_secret",
                content=(
                    "Cursor 正在检查代码片段，"
                    "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"  # pragma: allowlist secret nosemgrep
                ),
                context={
                    "provider": "cursor",
                    "endpoint_kind": "coding",
                    "host": "api5.cursor.sh",
                },
            )
        ))
        assert response.action == "audit"
        assert any(
            item.type == "secret" and item.category == "github_token"
            for item in response.findings
        )

    def test_check_input_does_not_flag_bare_digest_as_aws_secret(self):
        """网关日志里的摘要、trace id 不能误报为 AWS Secret"""
        random_digest = "9e" + "a" * 36 + "6b"
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_aws_secret_fp",
                content=f"tool_call_id=tc_93d5bdf6 evidence={random_digest}",
                context={
                    "provider": "glm",
                    "endpoint_kind": "agent-tool-call",
                },
            )
        ))
        categories = {item.category for item in response.findings}
        assert "aws_secret_key" not in categories
        assert "encoding_base64" not in categories
        assert "config_file" not in categories
        assert response.action == "allow"

    def test_check_input_with_id_card(self):
        """测试身份证输入"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_004",
                content="身份证: 12345678901234567X",  # pragma: allowlist secret nosemgrep
            )
        ))
        assert response.action == "audit"

    def test_check_input_safe(self):
        """测试安全输入"""
        response = _run(check_input_module.check_input(
            check_input_module.CheckInputRequest(
                request_id="test_005",
                content="这是一个正常的安全消息。",
            )
        ))
        assert response.action == "allow"


class TestCheckOutput:
    def test_check_output_empty(self):
        """测试空输出检查"""
        response = _run(check_output_module.check_output(
            check_output_module.CheckOutputRequest(request_id="test_001", content="")
        ))
        assert response.action == "allow"

    def test_check_output_with_pii(self):
        """测试带 PII 的输出"""
        response = _run(check_output_module.check_output(
            check_output_module.CheckOutputRequest(
                request_id="test_002",
                content="联系方式: test@example.com",
            )
        ))
        assert len(response.findings) > 0

    def test_check_output_passes_skip_semantic_to_engine(self, monkeypatch):
        captured = {}
        original = check_output_module.engine.check_output

        def _capture(request_id, content, context=None, skip_semantic=False):
            captured["skip_semantic"] = skip_semantic
            return original(
                request_id,
                content,
                context,
                skip_semantic=skip_semantic,
            )

        monkeypatch.setattr(check_output_module.engine, "check_output", _capture)
        response = _run(check_output_module.check_output(
            check_output_module.CheckOutputRequest(
                request_id="test_output_skip_semantic",
                content="联系方式: test@example.com",
                skip_semantic=True,
            )
        ))

        assert captured["skip_semantic"] is True
        assert len(response.findings) > 0

    def test_check_output_with_hazardous_chemical_instructions(self):
        """测试输出侧危险化学品合成指导检测"""
        response = _run(check_output_module.check_output(
            check_output_module.CheckOutputRequest(
                request_id="test_output_hazardous_chem",
                content=(
                    "关于氰化物制备，以下给出原料清单、合成步骤、"
                    "反应条件和剂量配比。"
                ),
            )
        ))
        assert response.action == "audit"
        assert any(
            item.category == "illegal_hazardous_chemical_instructions"
            for item in response.findings
        )


class TestSecurityTest:
    def test_security_test_endpoint(self):
        """测试安全测试端点"""
        response = _run(test_security_module.test_security(
            test_security_module.SecurityTestRequest(text="测试文本")
        ))
        assert hasattr(response, "findings")
        assert hasattr(response, "action")

    def test_security_test_with_phone(self):
        """测试安全测试端点 - 手机号"""
        response = _run(test_security_module.test_security(
            test_security_module.SecurityTestRequest(text="手机号: 13812345678")
        ))
        assert len(response.findings) > 0
        assert response.action in ["mask", "audit"]

    def test_security_test_with_aws_key(self):
        """测试安全测试端点 - AWS 密钥"""
        response = _run(test_security_module.test_security(
            test_security_module.SecurityTestRequest(
                text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret nosemgrep
            )
        ))
        assert response.action == "audit"

    def test_security_test_with_project_id(self):
        """测试安全测试端点 - 带项目 ID"""
        response = _run(test_security_module.test_security(
            test_security_module.SecurityTestRequest(
                text="测试文本",
                project_id="proj_001",
                model="gpt-4",
            )
        ))
        assert response.action == "allow"

    def test_security_test_latency_reported(self):
        """测试安全测试端点 - 延迟报告"""
        response = _run(test_security_module.test_security(
            test_security_module.SecurityTestRequest(text="测试延迟")
        ))
        assert isinstance(response.latency_ms, int)


def test_check_input_response_carries_build_and_raw(monkeypatch):
    monkeypatch.setenv("SECURITY_ENGINE_BUILD", "api-build-9")
    from app.detectors.engine import engine as live_engine
    live_engine.engine_build = "api-build-9"
    live_engine.rule_pack_version = "rp-7"
    req = check_input_module.CheckInputRequest(
        request_id="r-api-1", content="key AKIAIOSFODNN7EXAMPLE"
    )
    resp = _run(check_input_module.check_input(req))
    assert resp.engine_build == "api-build-9"
    assert resp.rule_pack_version == "rp-7"
    assert len(resp.raw_findings) >= 1


def test_check_input_accepts_content_source_and_user(monkeypatch):
    captured = {}
    from app.detectors import engine as engine_mod

    real = engine_mod.engine.check_input

    def spy(*args, **kwargs):
        captured["content_source"] = kwargs.get("content_source")
        captured["context"] = kwargs.get("context")
        return real(*args, **kwargs)

    monkeypatch.setattr(engine_mod.engine, "check_input", spy)
    req = check_input_module.CheckInputRequest(
        request_id="r-src-1", content="hello",
        content_source="user", project_id="proj_x", user_id="user_x",
    )
    _run(check_input_module.check_input(req))
    assert captured["content_source"] == "user"
    assert captured["context"]["project_id"] == "proj_x"
    assert captured["context"]["user_id"] == "user_x"


@pytest.mark.parametrize(
    ("raw", "want", "conflict"),
    [
        ([(b"x-jjdguard-internal-token", b" new-token\t")], "new-token", False),
        ([(b"x-newapi-internal-token", b"legacy-token")], "legacy-token", False),
        ([(b"X-JJDGuard-Internal-Token", b"same"), (b"x-newapi-internal-token", b"same")], "same", False),
        ([(b"x-jjdguard-internal-token", b"new-canary"), (b"x-newapi-internal-token", b"old-canary")], "", True),
        ([(b"x-jjdguard-internal-token", b"same"), (b"x-jjdguard-internal-token", b"same")], "same", False),
        ([(b"x-jjdguard-internal-token", b"one"), (b"x-jjdguard-internal-token", b"two")], "", True),
        ([(b"x-jjdguard-internal-token", b" \t"), (b"x-newapi-internal-token", b"legacy")], "legacy", False),
        ([(b"x-jjdguard-internal-token", b"one,two")], "", True),
    ],
)
def test_raw_internal_header_contract(raw, want, conflict):
    assert resolve_raw_headers(raw, b"x-jjdguard-internal-token", b"x-newapi-internal-token") == (want, conflict)


def test_internal_token_conflict_rejected_before_comparison_without_value_leak(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "expected")
    request = _request("/check-input/")
    request.scope["headers"] = [
        (b"x-jjdguard-internal-token", b"new-conflict-canary"),
        (b"x-newapi-internal-token", b"old-conflict-canary"),
    ]
    response = _run(main_module.require_internal_token(request, _ok_response))
    assert response.status_code == 401
    assert response.body == b'{"error":{"code":"internal_token_header_conflict"}}'
    assert b"canary" not in response.body
