"""
E2E 测试：完整用户场景测试

测试说明：
- 测试会自动获取必要的前置条件
- 只有服务不可用时才会 skip
- 覆盖关键用户流程
"""
import pytest
import httpx
import os
import uuid


# 服务地址
GATEWAY_URL = "http://localhost:8080"
CONTROL_PLANE_URL = "http://localhost:8081"
SECURITY_ENGINE_URL = "http://localhost:8000"

# Admin 凭据
ADMIN_USERNAME = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin123")
SECURITY_AUDIT_ONLY = os.getenv("SECURITY_AUDIT_ONLY", "").lower() in {"1", "true", "yes", "on"}


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
    client = httpx.AsyncClient()
    try:
        resp = await client.get(f"{GATEWAY_URL}/v1/models", timeout=2.0)
        return resp.status_code in [200, 401]
    except httpx.RequestError:
        return False
    finally:
        await client.aclose()


async def check_control_plane_available() -> bool:
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

    create_resp = await http_client.post(
        f"{CONTROL_PLANE_URL}/admin/v1/projects",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": f"E2E Test Project {uuid.uuid4().hex[:8]}"},
        timeout=5.0
    )
    if create_resp.status_code != 200:
        pytest.skip(f"Could not create project: {create_resp.status_code}")

    return create_resp.json()["id"]


async def create_test_api_key(http_client: httpx.AsyncClient, token: str) -> tuple:
    """
    创建测试用的 API key，返回 (full_key, key_id)。
    流程：确保项目存在 -> 创建 key（不传 user_id） -> 返回 full_key 和 key_id
    """
    project_id = await ensure_test_project(http_client, token)

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
    清理测试 key。
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


# ===== Tenant Onboarding =====

class TestTenantOnboarding:
    """租户入驻流程"""

    @pytest.mark.asyncio
    async def test_create_tenant_and_project(self):
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        try:
            login_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/login",
                json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
                timeout=5.0
            )
            if login_resp.status_code != 200:
                pytest.skip("Login failed")
            token = login_resp.json()["token"]

            tenant_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/tenants",
                headers={"Authorization": f"Bearer {token}"},
                json={"name": "Test Tenant E2E", "edition": "cloud"},
                timeout=5.0
            )
            assert tenant_resp.status_code == 200

            tenant_id = tenant_resp.json()["id"]
            project_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/projects",
                headers={"Authorization": f"Bearer {token}"},
                json={"name": "Test Project E2E", "tenant_id": tenant_id},
                timeout=5.0
            )
            assert project_resp.status_code == 200
        finally:
            await client.aclose()


# ===== Key Issuance =====

class TestKeyIssuance:
    """密钥签发流程"""

    @pytest.mark.asyncio
    async def test_create_and_revoke_key(self):
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        try:
            login_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/login",
                json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
                timeout=5.0
            )
            if login_resp.status_code != 200:
                pytest.skip("Login failed")
            token = login_resp.json()["token"]
            project_id = await ensure_test_project(client, token)

            key_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/keys",
                headers={"Authorization": f"Bearer {token}"},
                json={"project_id": project_id},
                timeout=5.0
            )
            assert key_resp.status_code == 200

            key_id = key_resp.json()["id"]
            revoke_resp = await client.post(
                f"{CONTROL_PLANE_URL}/admin/v1/keys/{key_id}/revoke",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            assert revoke_resp.status_code == 204
        finally:
            await client.aclose()


# ===== Security Block =====

class TestSecurityBlockCase:
    """安全阻止场景"""

    @pytest.mark.asyncio
    async def test_block_sensitive_request(self):
        # Verify security-engine is actually running (not Kong on same port)
        if not await check_service_available(SECURITY_ENGINE_URL, "security-engine"):
            pytest.skip("Security Engine not running")

        client = httpx.AsyncClient()
        try:
            check_resp = await client.post(
                f"{SECURITY_ENGINE_URL}/check-input/",
                json={
                    "request_id": "e2e_test_001",
                    "content": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                },
                timeout=10.0
            )
            assert check_resp.status_code == 200
            data = check_resp.json()
            assert data["action"] == ("audit" if SECURITY_AUDIT_ONLY else "block")
            assert any(f["type"] == "secret" for f in data["findings"])
        finally:
            await client.aclose()


# ===== Responses API E2E =====

class TestResponsesAPI:
    """Responses API 场景"""

    @pytest.mark.asyncio
    async def test_responses_endpoint_e2e(self):
        """完整 responses 流程"""
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        try:
            token = await get_admin_token(client)
            api_key, key_id = await create_test_api_key(client, token)

            resp = await client.post(
                f"{GATEWAY_URL}/v1/responses",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "input": "What is AI?"
                },
                timeout=30.0
            )

            # 验证不被 auth 拒绝，endpoint 已实现
            assert resp.status_code != 401, "Should not be unauthorized with valid key"
            assert resp.status_code != 403, "Should not be forbidden with valid key"
            assert resp.status_code != 404, "Endpoint should exist"
            assert resp.status_code != 501, "Endpoint should be implemented"

            # 合理状态码: 200(成功), 400(model/provider配置问题), 502/503(provider不可用)
            assert resp.status_code in [200, 400, 502, 503], f"Unexpected status: {resp.status_code}"

            if resp.status_code == 200:
                data = resp.json()
                assert data["object"] == "response"
                assert "output" in data
                assert len(data["output"]) > 0
            else:
                # 错误情况下必须返回具体的错误码
                data = resp.json()
                assert "error" in data, f"Expected error structure, got: {data}"
                assert "code" in data["error"], f"Expected error.code, got: {data}"
                # 必须是明确的错误码类型
                valid_error_codes = [
                    "model_not_configured",
                    "provider_not_configured",
                    "provider_unsupported",
                    "provider_unavailable",
                ]
                assert data["error"]["code"] in valid_error_codes, (
                    f"Expected specific error code in {valid_error_codes}, got: {data['error']['code']}"
                )
        finally:
            if 'key_id' in dir():
                await revoke_test_api_key(client, token, key_id)
            await client.aclose()

    @pytest.mark.asyncio
    async def test_responses_stream_rejected_e2e(self):
        """验证 stream=true 被拒绝"""
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        token = None
        key_id = None
        try:
            token = await get_admin_token(client)
            api_key, key_id = await create_test_api_key(client, token)

            resp = await client.post(
                f"{GATEWAY_URL}/v1/responses",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "input": "Hello",
                    "stream": True
                },
                timeout=10.0
            )

            # 必须返回 400
            assert resp.status_code == 400, f"Expected 400 for stream=true, got {resp.status_code}"
            data = resp.json()
            assert "error" in data
            assert data["error"]["code"] == "stream_not_supported"
        finally:
            if token and key_id:
                await revoke_test_api_key(client, token, key_id)
            await client.aclose()


# ===== Embeddings API E2E =====

class TestEmbeddingsAPI:
    """Embeddings API 场景"""

    @pytest.mark.asyncio
    async def test_embeddings_endpoint_e2e(self):
        """完整 embeddings 流程"""
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        token = None
        key_id = None
        try:
            token = await get_admin_token(client)
            api_key, key_id = await create_test_api_key(client, token)

            resp = await client.post(
                f"{GATEWAY_URL}/v1/embeddings",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "text-embedding-ada-002",
                    "input": "Hello world"
                },
                timeout=30.0
            )

            # 验证 endpoint 已实现，不应返回 auth 错误（key 是刚创建的）
            assert resp.status_code != 404, "Embeddings endpoint should exist"
            assert resp.status_code != 501, "Embeddings endpoint should be implemented"
            assert resp.status_code != 401, "Should not be unauthorized with valid key"
            assert resp.status_code != 403, "Should not be forbidden with valid key"

            # 验证响应必须是以下情况之一：
            # - 200: 成功（需要真实 embedding provider）
            # - 400: model_not_configured / provider_not_configured / provider_unsupported
            # - 502/503: provider_unavailable
            assert resp.status_code in [200, 400, 502, 503], f"Unexpected status: {resp.status_code}"

            if resp.status_code == 200:
                data = resp.json()
                assert data["object"] == "list"
                assert "data" in data
                assert len(data["data"]) > 0
                assert "embedding" in data["data"][0]
            else:
                # 错误情况下必须返回具体的错误码
                data = resp.json()
                assert "error" in data, f"Expected error structure, got: {data}"
                assert "code" in data["error"], f"Expected error.code, got: {data}"
                # 必须是明确的错误码类型
                valid_error_codes = [
                    "model_not_configured",
                    "provider_not_configured",
                    "provider_unsupported",
                    "provider_unavailable",
                ]
                assert data["error"]["code"] in valid_error_codes, (
                    f"Expected specific error code in {valid_error_codes}, got: {data['error']['code']}"
                )
        finally:
            if token and key_id:
                await revoke_test_api_key(client, token, key_id)
            await client.aclose()


# ===== Agent Sessions E2E =====

class TestAgentSessions:
    """Agent Session 场景"""

    @pytest.mark.asyncio
    async def test_agent_sessions_list_e2e(self):
        """验证 agent sessions list API"""
        if not await check_control_plane_available():
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        try:
            token = await get_admin_token(client)

            resp = await client.get(
                f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "data" in data
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_gateway_with_session_creates_record_e2e(self):
        """验证带 session_id 的 gateway 请求会创建记录"""
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        token = None
        key_id = None
        try:
            token = await get_admin_token(client)
            api_key, key_id = await create_test_api_key(client, token)

            session_id = f"e2e-session-{uuid.uuid4().hex[:8]}"

            resp = await client.post(
                f"{GATEWAY_URL}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "X-JJDGuard-Session-Id": session_id
                },
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}]
                },
                timeout=30.0
            )

            # 验证不被 auth 拒绝
            assert resp.status_code != 401
            assert resp.status_code != 403
            assert resp.status_code != 404

            # 查询 session 列表，验证能找到刚创建的 session
            sessions_resp = await client.get(
                f"{CONTROL_PLANE_URL}/admin/v1/agent-sessions",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0
            )
            assert sessions_resp.status_code == 200

            sessions_data = sessions_resp.json()
            found = False
            for session in sessions_data.get("data", []):
                if session.get("session_id") == session_id:
                    found = True
                    break

            # 关键断言：请求通过了 gateway auth（非401），session 必须被记录
            # 这是 agent session 闭环的核心验证 - 不能用宽松断言
            assert found, (
                f"Session {session_id} must be found in control-plane after gateway request "
                f"(gateway returned {resp.status_code})"
            )
        finally:
            if token and key_id:
                await revoke_test_api_key(client, token, key_id)
            await client.aclose()


# ===== Full Flow E2E =====

class TestFullFlowE2E:
    """完整流程"""

    @pytest.mark.asyncio
    async def test_complete_user_flow(self):
        """
        完整用户流程：
        1. 登录
        2. 创建 API key
        3. 用 key 调用 gateway
        4. 验证响应
        """
        gateway_ok = await check_gateway_available()
        cp_ok = await check_control_plane_available()

        if not gateway_ok:
            pytest.skip("Gateway not running")
        if not cp_ok:
            pytest.skip("Control Plane not running")

        client = httpx.AsyncClient()
        token = None
        key_id = None
        try:
            # Step 1: 登录
            token = await get_admin_token(client)

            # Step 2: 创建 API key
            api_key, key_id = await create_test_api_key(client, token)

            # Step 3: 调用 gateway
            resp = await client.post(
                f"{GATEWAY_URL}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Say hello in one word"}]
                },
                timeout=30.0
            )

            # Step 4: 验证响应
            assert resp.status_code != 401, "Should not be unauthorized with valid key"
            assert resp.status_code != 403, "Should not be forbidden with valid key"
            assert resp.status_code != 404, "Endpoint should exist"
            assert resp.status_code != 501, "Endpoint should be implemented"

            if resp.status_code == 200:
                data = resp.json()
                assert "choices" in data
                assert len(data["choices"]) > 0
                assert "message" in data["choices"][0]
            elif resp.status_code >= 400:
                data = resp.json()
                assert "error" in data
                assert "code" in data["error"]
        finally:
            if token and key_id:
                await revoke_test_api_key(client, token, key_id)
            await client.aclose()
