"""
P2-1 Layer 4：security-engine 启动装配（FastAPI lifespan）测试。

验证：
  - 未配置 CONTROL_PLANE_URL → 加载器禁用，服务照常启动（向后兼容，不构造 loader）
  - 配置后 → 启动即拉取一次规则包 + 创建后台热更新任务；关闭时干净退出
装配为薄胶水：拉取/匹配逻辑由 test_rule_pack_loader 全覆盖，这里只锁装配行为，
且刻意不依赖后台协程的调度时序（避免 flaky）。
"""
import anyio
import asyncio
import pytest

import app.main as main_module


class _FakeLoader:
    instances = []

    def __init__(self, config):
        self.config = config
        self.refresh_calls = 0
        _FakeLoader.instances.append(self)

    def refresh_once(self, engine):
        self.refresh_calls += 1
        return True

    def refresh_and_acknowledge(self, engine):
        return self.refresh_once(engine)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    original_audit_only = main_module.engine.audit_only
    for var in (
        "CONTROL_PLANE_URL",
        "JJD_INTERNAL_API_SECRET",
        "SECURITY_TENANT_ID",
        "SECURITY_RULE_REFRESH_SECONDS",
        "SECURITY_RULE_FETCH_TIMEOUT",
        "SECURITY_RULE_PACK_ATTESTATION_TOKEN",
        "SECURITY_AUDIT_ONLY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    main_module.engine.audit_only = True
    _FakeLoader.instances = []
    yield
    main_module.engine.audit_only = original_audit_only


def test_lifespan_disabled_when_no_control_plane_url(monkeypatch):
    monkeypatch.setattr(main_module, "RulePackLoader", _FakeLoader)

    def _must_not_run(*args, **kwargs):
        raise AssertionError("禁用态不应启动 run_refresh_loop")

    monkeypatch.setattr(main_module, "run_refresh_loop", _must_not_run)

    async def _run():
        async with main_module.lifespan(main_module.app):
            pass

    anyio.run(_run)

    # 未配置 control-plane：不构造 loader、不起后台任务
    assert _FakeLoader.instances == []


def test_lifespan_fetches_once_and_starts_background_loop(monkeypatch, caplog):
    monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp:8080")
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "tok")
    monkeypatch.setenv("SECURITY_RULE_REFRESH_SECONDS", "999999")
    monkeypatch.setattr(main_module, "RulePackLoader", _FakeLoader)
    caplog.set_level("INFO")

    async def _run_sync_inline(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(main_module.anyio.to_thread, "run_sync", _run_sync_inline)

    invocations = []

    def fake_run_refresh_loop(loader, engine):
        # 同步记录「被调用」（确定性），返回一个可被取消的协程交给 create_task
        invocations.append((loader, engine))

        async def _coro():
            await asyncio.Event().wait()

        return _coro()

    monkeypatch.setattr(main_module, "run_refresh_loop", fake_run_refresh_loop)

    async def _run():
        async with main_module.lifespan(main_module.app):
            for _ in range(100):
                if _FakeLoader.instances[0].refresh_calls == 1:
                    break
                await asyncio.sleep(0.01)

    anyio.run(_run)

    # 启动同步拉取一次
    assert len(_FakeLoader.instances) == 1
    assert _FakeLoader.instances[0].refresh_calls == 1
    # 后台热更新任务已创建，且与启动用的是同一个 loader
    assert len(invocations) == 1
    assert invocations[0][0] is _FakeLoader.instances[0]
    assert "每 3600s 刷新一次" in caplog.text
    # 走到这里（with 已退出）即证明 shutdown 取消后台任务未抛异常


def test_lifespan_does_not_wait_for_initial_control_plane_fetch(monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp:8080")
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "tok")
    monkeypatch.setattr(main_module, "RulePackLoader", _FakeLoader)
    release_fetch = asyncio.Event()

    async def blocked_run_sync(func, *args, **kwargs):
        await release_fetch.wait()
        return func(*args, **kwargs)

    async def idle_refresh_loop(loader, engine):
        await asyncio.Event().wait()

    monkeypatch.setattr(main_module.anyio.to_thread, "run_sync", blocked_run_sync)
    monkeypatch.setattr(main_module, "run_refresh_loop", idle_refresh_loop)

    async def _run():
        async with main_module.lifespan(main_module.app):
            assert _FakeLoader.instances
            assert _FakeLoader.instances[0].refresh_calls == 0
            release_fetch.set()
            await asyncio.sleep(0)
            await asyncio.sleep(0)

    anyio.run(_run)


def test_lifespan_accepts_strict_boot_mode_when_actions_are_consistent(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    main_module.engine.audit_only = False

    async def _run():
        async with main_module.lifespan(main_module.app):
            assert main_module.engine.audit_only is False

    anyio.run(_run)


def test_lifespan_allows_managed_runtime_to_replace_safe_boot_default(monkeypatch):
    from app import semantic_config_loader

    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    main_module.engine.audit_only = True
    calls = []

    def _apply_managed_strict_runtime():
        calls.append("start")
        # 代表经过 attestation 的 control-plane 完整投影原子应用。
        main_module.engine.audit_only = False

    monkeypatch.setattr(semantic_config_loader, "start", _apply_managed_strict_runtime)

    async def _run():
        async with main_module.lifespan(main_module.app):
            assert main_module.engine.audit_only is False

    anyio.run(_run)

    assert calls == ["start"]


def _run_lifespan():
    async def _run():
        async with main_module.lifespan(main_module.app):
            pass

    anyio.run(_run)


def test_lifespan_loads_capability_docs_once_at_startup(monkeypatch):
    calls = []
    real = main_module.load_capability_docs
    monkeypatch.setattr(main_module, "load_capability_docs", lambda: calls.append(1) or real())
    _run_lifespan()
    assert calls == [1]


def test_lifespan_fails_when_capability_docs_are_broken(monkeypatch, caplog):
    def broken():
        raise main_module.CapabilityDocError("data_leak.json: JSON 语法错误")

    monkeypatch.setattr(main_module, "load_capability_docs", broken)
    with pytest.raises(main_module.CapabilityDocError):
        _run_lifespan()
    assert "capability docs" in caplog.text


def test_lifespan_fails_when_capability_docs_are_empty(monkeypatch, caplog):
    monkeypatch.setattr(main_module, "load_capability_docs", lambda: {})
    with pytest.raises(RuntimeError):
        _run_lifespan()
    assert "capability docs" in caplog.text


def test_lifespan_fails_when_capability_docs_cannot_be_decoded(monkeypatch, caplog):
    def broken():
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(main_module, "load_capability_docs", broken)
    with pytest.raises(UnicodeDecodeError):
        _run_lifespan()
    assert "capability docs" in caplog.text


def test_capability_docs_are_checked_before_other_startup_selfchecks(monkeypatch):
    order = []
    monkeypatch.setattr(main_module, "load_capability_docs", lambda: order.append("docs") or {"x": 1})
    monkeypatch.setattr(main_module, "assert_runtime_policy_consistency", lambda engine: order.append("policy"))
    _run_lifespan()
    assert order[:2] == ["docs", "policy"]
