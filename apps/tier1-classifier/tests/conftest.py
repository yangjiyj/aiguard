"""测试隔离：打分器是进程级单例（app.classifier._SCORER），跨测试会泄漏。

每个测试后重置为未注入状态，避免某测试注入的 stub 污染后续测试
（如 B-1 的 /health model_loaded 断言、no-scorer 503 断言）。
"""
import importlib

import pytest


@pytest.fixture(autouse=True)
def _reset_scorer():
    yield
    import app.classifier as clf

    importlib.reload(clf)
