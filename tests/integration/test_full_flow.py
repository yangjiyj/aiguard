"""
集成测试：Gateway + Security Engine + Control Plane
测试请求流经各组件时的行为

测试说明：
- 测试会自动获取必要的前置条件（通过 control-plane 创建 API key）
- 只有服务不可用时才会 skip
- 不会因为"缺少配置"而 skip
"""
import pytest
import httpx
import json
import os
import uuid


# 服务地址
GATEWAY_URL = "http://localhost:8080"
CONTROL_PLANE_URL = "http://localhost:8081"
SECURITY_ENGINE_URL = "http://localhost:8000"

# 测试用 admin 凭据
ADMIN_USERNAME = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin123")


@pytest.fixture
def http_client():
    return httpx.AsyncClient()


# ===== Helper Functions =====

async def check_service_available(url: str, expected_service: str = None, timeout: float = 2.0) -> bool:
    """Check if a service is available and verify it's the correct service"""
    client = httpx.AsyncClient()
    try:
        resp = await client.get(f"{url}/health", timeout=timeout)
        if resp.status_code != 200:
            return False
        # Verify service identity if expected_service specified
        if expected_service:
            try:
                data = resp.json()
                if data.get("service") != expected_service:
                    return False
            except:
                return False
        return True
    except httpx.RequestError:
        # Covers ConnectError, TimeoutException, RemoteProtocolError, etc.
        return False
    finally:
        await client.aclose()


async def check_gateway_available() -> bool:
    """Check gateway availability"""
    client = httpx.AsyncClient()
    try:
        resp = await client.get(f"{GATEWAY_URL}/v1/models", timeout=2.0)
        return resp.status_code in [200, 401]
    except httpx.RequestError:
        return False
    finally:
        await client.aclose()


async def check_control_plane_available() -> bool:
    """Check control-plane availability"""
    client = httpx.AsyncClient()
    try:
        resp = await client.post(
            f"{CONTROL_PLANE_URL}/admin/v1/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=2.0
        )
        return resp.status_code == 200
    except httpx.RequestError:
        return False
    finally:
        await client.aclose()


async def get_admin_token(http_client: httpx.AsyncClient) -> str:
    """登录获取 admin token"""
    resp = await http_client.post(
        f"{CONTROL_PLANE_URL}/admin/v1/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=5.0
    )
    if resp.status_code != 200:
        pytest.skip(f"Login failed: {resp.status_code}")
    return resp.json()["token"]


async def ensure_test_project(http_client: httpx.AsyncClient, token: str) -> str:
    """
    确保测试项目存在，返回 project_id。
    优先选择 seed 的默认项目 (project_default)，确保模型路由条件可用。
    """
    # 获取项目列表
    projects_resp = await http_client.get(
        f"{CONTROL_PLANE_URL}/admin/v1/projects",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5.0
    )
    if projects_resp.status_code != 200:
        pytest.skip(f"Could not list projects: {projects_resp.status_code}")

    projects_data = projects_resp.json()
    # 优先选择 seed 的默认项目（通常具备完整的模型路由条件）
    for project in projects_data.get("data", []):
        if project.get("id") == "project_default" and project.get("status") == "active":
            return project["id"]

    # 如果没有找到默认项目，选择其他活跃项目
    for project in projects_data.get("data", []):
        if project.get("status") == "active":
            return project["id"]

    # 如果没有活跃项目，创建一个测试项目
    create_resp = await http_client.post(
        f"{CONTROL_PLANE_URL}/admin/v1/projects",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": f"Test Project {uuid.uuid4().hex[:8]}"},
        timeout=5.0
    )
    if create_resp.status_code != 200:
        pytest.skip(f"Could not create project: {create_resp.status_code}")

    return create_resp.json()["id"]


async def create_test_api_key(http_client: httpx.AsyncClient, token: str) -> tuple:
    """
    创建测试用的 API key，返回 (full_key, key_id)。

    流程：
    1. 确保存在测试项目
    2. 创建一个新的 key（不传 user_id，自动使用当前登录用户）
    3. 返回 full_key（创建时唯一可见）和 key_id（用于清理）
    """
    # 确保项目存在
    project_id = await ensure_test_project(http_client, token)

    # 创建新的 key（不传 user_id，自动使用当前登录用户）
    create_resp = await http_client.post(
        f"{CONTROL_PLANE_URL}/admin/v1/keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"project_id": project_id},
        timeout=5.0
    )
    if create_resp.status_code != 200:
        pytest.skip(f"Could not create key: {create_resp.status_code} - {create_resp.text}")

    data = create_resp.json()
    full_key = data.get("full_key")
    key_id = data.get("id")

    if not full_key:
        pytest.skip("Key creation response missing full_key")

    return full_key, key_id


async def revoke_test_api_key(http_client: httpx.AsyncClient, token: str, key_id: str) -> bool:
    """
    清理测试 key，调用 revoke API。
    返回是否成功清理。
    """
    try:
        revoke_resp = await http_client.post(
            f"{CONTROL_PLANE_URL}/admin/v1/keys/{key_id}/revoke",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        return revoke_resp.status_code in [200, 204]
    except:
        return False


# ===== Gateway Integration Tests =====

class TestGatewayIntegration:
    @pytest.mark.asyncio
    async def test_health_checks(self, http_client):
        """测试各服务健康检查"""
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()
        # Verify security-engine is actually running (not Kong on same port)
        se_ok = await check_service_available(SECURITY_ENGINE_URL, "security-engine")

        # 至少有一个服务运行才继续
        if not (gateway_ok or cp_ok or se_ok):
            pytest.skip("No services running")

        if gateway_ok:
            resp = await http_client.get(f"{GATEWAY_URL}/v1/models", timeout=5.0)
            assert resp.status_code in [200, 401]

        if cp_ok:
            resp = await http_client.get(f"{CONTROL_PLANE_URL}/admin/v1/tenants", timeout=5.0)
            assert resp.status_code in [200, 401]

        if se_ok:
            resp = await http_client.get(f"{SECURITY_ENGINE_URL}/health", timeout=5.0)
            assert resp.status_code == 200
            data = resp.json()
            assert data.get("service") == "security-engine"


# ===== Control Plane Integration Tests =====

class TestControlPlaneIntegration:
    @pytest.mark.asyncio
    async def test_login_integration(self, http_client):
        """测试控制面登录"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        resp = await http_client.post(
            f"{CONTROL_PLANE_URL}/admin/v1/login",
            json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            timeout=5.0
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["user"]["username"] == ADMIN_USERNAME


# ===== Security Engine Integration Tests =====

class TestSecurityEngineIntegration:
    @pytest.mark.asyncio
    async def test_check_input_integration(self, http_client):
        """测试安全引擎输入检查"""
        if not await check_service_available(SECURITY_ENGINE_URL, "security-engine"):
            pytest.skip("Security Engine not running")

        resp = await http_client.post(
            f"{SECURITY_ENGINE_URL}/check-input/",
            json={
                "request_id": "integration_test_001",
                "content": "手机号: 13812345678, 身份证: 12345678901234567X"
            },
            timeout=10.0
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["findings"]) >= 2


# ===== Responses API Integration Tests =====

class TestResponsesAPIIntegration:
    """测试 /v1/responses API"""

    @pytest.mark.asyncio
    async def test_responses_non_stream_with_key(self, http_client):
        """
        验证 /v1/responses 非流式路径：
        1. 通过 control-plane 创建 API key
        2. 用 key 调用 gateway
        3. 验证返回格式
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        # 获取 admin token 和创建测试 API key
        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 调用 responses endpoint
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/responses",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "input": "Hello, how are you?"
                },
                timeout=30.0
            )

            # 验证响应状态码 - 必须是合理的 provider/model 层面结果
            # 不应该出现 401（key 是刚创建的有效 key）或 403（tenant 应该有权限）或 404/501（endpoint 已实现）
            assert resp.status_code != 401, "Should not be unauthorized with valid created key"
            assert resp.status_code != 403, "Should not be forbidden with valid created key"
            assert resp.status_code != 404, "/v1/responses endpoint should exist"
            assert resp.status_code != 501, "/v1/responses endpoint should be implemented"

            # 合理状态码: 200(成功), 400(model/provider配置问题), 502/503(provider不可用)
            assert resp.status_code in [200, 400, 502, 503], f"Unexpected status: {resp.status_code}"

            # 如果成功，验证格式
            if resp.status_code == 200:
                data = resp.json()
                assert "id" in data
                assert data["object"] == "response"
                assert "output" in data
                assert len(data["output"]) > 0

            # 如果是错误，验证错误格式
            if resp.status_code >= 400:
                data = resp.json()
                assert "error" in data, f"Expected error structure, got: {data}"
                assert "code" in data["error"], f"Expected error.code, got: {data}"
                # 验证错误码是合理的
                assert data["error"]["code"] in [
                    "model_not_configured",
                    "provider_not_configured",
                    "provider_unavailable",
                    "provider_unsupported"
                ]
        finally:
            # 清理测试 key
            await revoke_test_api_key(http_client, token, key_id)

    @pytest.mark.asyncio
    async def test_responses_stream_rejected_with_key(self, http_client):
        """
        验证 /v1/responses 拒绝 stream=true：
        - 返回 400 Bad Request
        - 错误码 stream_not_supported
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 发送 stream=true 请求
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/responses",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "input": "Hello",
                    "stream": True
                },
                timeout=10.0
            )

            # 必须返回 400，不能是其他状态
            assert resp.status_code == 400, f"Expected 400 for stream=true, got {resp.status_code}"

            data = resp.json()
            assert "error" in data
            assert data["error"]["code"] == "stream_not_supported", f"Expected stream_not_supported, got {data['error']['code']}"
            assert "message" in data["error"]
        finally:
            await revoke_test_api_key(http_client, token, key_id)


# ===== Embeddings API Integration Tests =====

class TestEmbeddingsAPIIntegration:
    """测试 /v1/embeddings API"""

    @pytest.mark.asyncio
    async def test_embeddings_endpoint_accessible(self, http_client):
        """
        验证 /v1/embeddings endpoint 可访问：
        1. 通过 control-plane 创建 API key
        2. 用 key 调用 gateway embeddings
        3. 验证响应格式和错误码
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 调用 embeddings endpoint
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/embeddings",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "text-embedding-ada-002",
                    "input": "Hello world"
                },
                timeout=30.0
            )

            # endpoint 已实现，不应返回 404 或 501 或 auth 错误（key 是刚创建的）
            assert resp.status_code != 404, "Embeddings endpoint should exist"
            assert resp.status_code != 501, "Embeddings endpoint should be implemented"
            assert resp.status_code != 401, "Should not be unauthorized with valid created key"
            assert resp.status_code != 403, "Should not be forbidden with valid created key"

            # 验证响应必须是以下情况之一：
            # - 200: 成功（需要真实 embedding provider）
            # - 400: model_not_configured / provider_not_configured / provider_unsupported
            # - 502/503: provider_unavailable
            assert resp.status_code in [200, 400, 502, 503], f"Unexpected status: {resp.status_code}"

            # 如果成功，验证 embeddings 格式
            if resp.status_code == 200:
                data = resp.json()
                assert data["object"] == "list"
                assert "data" in data
                assert len(data["data"]) > 0
                assert "embedding" in data["data"][0]
                assert len(data["data"][0]["embedding"]) > 0

            # 如果是错误，验证错误格式和具体错误码
            data = resp.json()
            assert "error" in data, f"Expected error structure, got: {data}"
            assert "code" in data["error"], f"Expected error.code, got: {data}"

            # 错误码必须是明确的类型，不能是模糊的 invalid_request
            valid_error_codes = [
                "model_not_configured",      # 模型未配置
                "provider_not_configured",   # provider credentials 未配置
                "provider_unsupported",      # provider 不支持 embeddings (如 Anthropic)
                "provider_unavailable",      # provider 不可用
            ]
            assert data["error"]["code"] in valid_error_codes, (
                f"Expected specific error code in {valid_error_codes}, got: {data['error']['code']}"
            )
        finally:
            await revoke_test_api_key(http_client, token, key_id)

    @pytest.mark.asyncio
    async def test_embeddings_anthropic_unsupported_via_gateway(self, http_client):
        """
        验证 Anthropic embeddings 返回 provider_unsupported：
        - 使用 Anthropic 类型的模型请求 embeddings
        - 验证返回正确的错误码
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 使用 Anthropic 模型名称请求 embeddings
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/embeddings",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "claude-3-sonnet",  # Anthropic 模型
                    "input": "Hello world"
                },
                timeout=10.0
            )

            # endpoint 已实现，不应返回 auth 错误（key 是刚创建的）
            assert resp.status_code != 404, "Embeddings endpoint should exist"
            assert resp.status_code != 501, "Embeddings endpoint should be implemented"
            assert resp.status_code != 401, "Should not be unauthorized with valid created key"
            assert resp.status_code != 403, "Should not be forbidden with valid created key"

            # 验证响应必须是以下情况之一：
            # - 400: model_not_configured / provider_not_configured / provider_unsupported
            # - 502/503: provider_unavailable
            # Anthropic 不支持 embeddings endpoint，如果配置指向 Anthropic 应返回 provider_unsupported
            assert resp.status_code in [400, 502, 503], f"Unexpected status: {resp.status_code}"

            data = resp.json()
            assert "error" in data, f"Expected error structure, got: {data}"
            assert "code" in data["error"], f"Expected error.code, got: {data}"

            # 错误码必须是以下之一（不含模糊的 invalid_request）
            valid_error_codes = [
                "model_not_configured",      # 模型未配置
                "provider_not_configured",   # provider credentials 未配置
                "provider_unsupported",      # Anthropic 不支持 embeddings
                "provider_unavailable",      # provider 不可用
            ]
            assert data["error"]["code"] in valid_error_codes, (
                f"Expected specific error code in {valid_error_codes}, got: {data['error']['code']}"
            )
        finally:
            await revoke_test_api_key(http_client, token, key_id)


# ===== Agent Session Integration Tests =====

class TestAgentSessionIntegration:
    """测试 agent session 集成"""

    @pytest.mark.asyncio
    async def test_agent_sessions_stats_compat_api(self, http_client):
        """验证 /admin/v1/agent-sessions/stats 不会被误识别为会话详情"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)

        resp = await http_client.get(
            f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_agent_sessions_list_api(self, http_client):
        """验证 /admin/v1/agent-sessions list API"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)

        resp = await http_client.get(
            f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data
        assert isinstance(data["data"], list)

    @pytest.mark.asyncio
    async def test_agent_session_detail_api(self, http_client):
        """验证 /admin/v1/agent-sessions/{id} detail API"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)

        # 先获取列表
        list_resp = await http_client.get(
            f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        assert list_resp.status_code == 200

        data = list_resp.json()
        if len(data["data"]) == 0:
            # 没有 session 时，跳过 detail 测试（可以测试创建流程）
            pytest.skip("No existing sessions - test gateway request flow instead")

        # 获取详情
        session_id = data["data"][0]["session_id"]
        detail_resp = await http_client.get(
            f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions/{session_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["session_id"] == session_id

    @pytest.mark.asyncio
    async def test_gateway_request_creates_session(self, http_client):
        """
        验证带 session_id 的 gateway 请求会创建 session 记录：
        1. 发送带 X-JJDGuard-Session-Id header 的请求
        2. 验证请求被处理（不因 auth 失败）
        3. 验证 session 出现在 control-plane 查询结果中
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        # 生成唯一 session_id
        test_session_id = f"test-session-{uuid.uuid4().hex[:8]}"

        try:
            # 发送带 session_id header 的请求
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "X-JJDGuard-Session-Id": test_session_id
                },
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}]
                },
                timeout=30.0
            )

            # 验证请求被处理（不应是 401/403，因为 key 是刚创建的有效 key）
            assert resp.status_code != 401, "Should not be unauthorized with valid key"
            assert resp.status_code != 403, "Should not be forbidden with valid key"
            assert resp.status_code != 404, "Endpoint should exist"

            # 不管 provider 成功与否，session 应该被记录（gateway 在 envelope 创建时就 upsert）
            # 查询 control-plane 验证 session 存在
            sessions_resp = await http_client.get(
                f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            assert sessions_resp.status_code == 200

            sessions_data = sessions_resp.json()
            assert "data" in sessions_data

            # 必须找到刚创建的 session - gateway 在请求进入 provider 层前就 upsert
            # 如果请求返回 200/400/502/503（通过了 auth + model routing），session 必须存在
            # 如果请求返回 model_not_configured（503），表示请求在 model resolution 阶段失败
            # 此时 session 是否创建取决于实现，但 auth 成功后 session 应被记录
            found_session = None
            for session in sessions_data["data"]:
                if session.get("session_id") == test_session_id:
                    found_session = session
                    break

            # 关键断言：请求通过了 gateway auth（非401），session 必须被记录
            # 这是 agent session 闭环的核心验证
            assert found_session is not None, (
                f"Session {test_session_id} must be found in control-plane after gateway request "
                f"(gateway returned {resp.status_code})"
            )
            assert found_session["session_id"] == test_session_id
            assert "request_count" in found_session
            assert found_session["request_count"] >= 1, "Session must have at least 1 request recorded"
        finally:
            await revoke_test_api_key(http_client, token, key_id)


# ===== Models Sync Integration Tests =====

class TestModelsSyncIntegration:
    """测试模型同步功能"""

    @pytest.mark.asyncio
    async def test_models_sync_requires_provider_id(self, http_client):
        """验证不传 provider_id 返回 400"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)

        resp = await http_client.post(
            f"{CONTROL_PLANE_URL}/admin/v1/models/sync",
            headers={"Authorization": f"Bearer {token}"},
            json={},
            timeout=10.0
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"]["code"] == "invalid_request"

    @pytest.mark.asyncio
    async def test_models_sync_invalid_provider_forbidden(self, http_client):
        """验证无效 provider_id 返回 403/404"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)

        resp = await http_client.post(
            f"{CONTROL_PLANE_URL}/admin/v1/models/sync",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_id": "invalid_provider_xyz"},
            timeout=10.0
        )
        # 应返回 403 或 404（provider not found）
        assert resp.status_code in [403, 404]


# ===== Error Contract Verification Tests =====

class TestErrorContractVerification:
    """验证 gateway 错误响应契约"""

    @pytest.mark.asyncio
    async def test_gateway_error_response_format(self, http_client):
        """
        验证 gateway 错误响应格式：
        - error 结构
        - code 字段
        - message 字段
        - request_id 字段
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        token = await get_admin_token(http_client)
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 发送一个会导致错误的请求（无效模型）
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "invalid-model-name",
                    "messages": [{"role": "user", "content": "Hello"}]
                },
                timeout=10.0
            )

            # 应该返回错误（不是 200）
            assert resp.status_code >= 400, f"Expected error status, got {resp.status_code}"
            assert resp.status_code != 401, "Should not be unauthorized with valid key"

            # 验证错误格式
            data = resp.json()
            assert "error" in data, f"Expected error structure, got: {data}"
            assert "code" in data["error"], f"Expected error.code, got: {data}"
            assert "message" in data["error"], f"Expected error.message, got: {data}"
            assert "request_id" in data["error"], f"Expected error.request_id, got: {data}"

            # 验证错误码是合理的
            assert data["error"]["code"] in [
                "model_not_configured",
                "provider_not_configured",
                "provider_unavailable",
                "invalid_request"
            ]
        finally:
            await revoke_test_api_key(http_client, token, key_id)

    @pytest.mark.asyncio
    async def test_unauthorized_response_format(self, http_client):
        """验证未认证请求返回正确格式"""
        if not await check_gateway_available():
            pytest.skip("Gateway not running")

        # 无 API key 的请求
        resp = await http_client.post(
            f"{GATEWAY_URL}/v1/chat/completions",
            json={
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}]
            },
            timeout=5.0
        )

        # 必须返回 401
        assert resp.status_code == 401, f"Expected 401 for unauthorized request, got {resp.status_code}"

        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == "unauthorized"
        assert "message" in data["error"]


# ===== Full Request Flow Tests =====

class TestFullRequestFlow:
    """完整请求流程测试"""

    @pytest.mark.asyncio
    async def test_full_flow_with_services(self, http_client):
        """
        完整流程：
        1. 登录 control-plane
        2. 创建 API key
        3. 用 key 调用 gateway
        4. 验证响应格式
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        # 登录
        token = await get_admin_token(http_client)

        # 创建 API key
        api_key, key_id = await create_test_api_key(http_client, token)

        try:
            # 调用 gateway
            resp = await http_client.post(
                f"{GATEWAY_URL}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Say hello"}]
                },
                timeout=30.0
            )

            # 验证不被 auth 拒绝（key 是刚创建的）
            assert resp.status_code != 401, "Should not be unauthorized with valid key"
            assert resp.status_code != 403, "Should not be forbidden with valid key"
            assert resp.status_code != 404, "Endpoint should exist"
            assert resp.status_code != 501, "Endpoint should be implemented"

            # 验证格式
            if resp.status_code == 200:
                data = resp.json()
                assert "choices" in data
                assert len(data["choices"]) > 0
                assert "message" in data["choices"][0]
            elif resp.status_code >= 400:
                data = resp.json()
                assert "error" in data
                assert "code" in data["error"]
                # 应该是明确的错误码
                assert data["error"]["code"] in [
                    "model_not_configured",
                    "provider_not_configured",
                    "provider_unavailable",
                    "rate_limited",
                    "quota_exceeded"
                ]
        finally:
            await revoke_test_api_key(http_client, token, key_id)
