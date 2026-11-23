import pytest

import app.detectors.llm_judge as _lj


@pytest.fixture(autouse=True)
def _reset_judge_breakers():
    """每个测试前清空裁判熔断器状态，避免跨用例污染（模块级注册表）。"""
    _lj._reset_breakers()
    yield
    _lj._reset_breakers()


@pytest.fixture(autouse=True)
def _reset_file_readiness_cache():
    """Dependency/asset mocks must not poison the next test's real OCR probe."""
    from app import file_readiness
    file_readiness._capability_cache = None
    yield
    file_readiness._capability_cache = None


def _reset_process_state():
    from app import feature_flags as ff
    from app import file_inspector

    ff._OVERRIDES = {}
    file_inspector.replace_file_policy(dict(file_inspector._EMPTY_RUNTIME_POLICY))


@pytest.fixture(autouse=True)
def _reset_overrides_and_file_policy():
    """进程级 override（feature_flags._OVERRIDES）和运行时文件策略（file_inspector._RUNTIME_POLICY）
    每个用例前后都清回初始状态：test_main_lifespan 等用例加载配置、规则包后不清理，会串到后面的用例。"""
    _reset_process_state()
    yield
    _reset_process_state()
