"""FIX-3：ONNX 推理线程数须由 env TIER1_THREADS 可调（默认 2），不得硬编码。

多核客户机可调高 intra_op_num_threads 提吞吐；单核/资源受限可调低。
解析逻辑抽成 _resolve_threads() 纯函数，便于在无 onnxruntime/transformers
依赖的环境下独立测试（load_model_scorer 会在 import 这些重依赖时早退）。
"""
import os

import app.model as model


def _set_env(monkeypatch, val):
    # The P1 tier fallback must not leak in from the ambient test environment.
    monkeypatch.delenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", raising=False)
    if val is None:
        monkeypatch.delenv("TIER1_THREADS", raising=False)
    else:
        monkeypatch.setenv("TIER1_THREADS", val)


def test_resolve_threads_defaults_to_2(monkeypatch):
    """未设置 TIER1_THREADS → 默认 2（与历史硬编码行为一致，零回归）。"""
    _set_env(monkeypatch, None)
    assert model._resolve_threads() == 2


def test_resolve_threads_reads_env(monkeypatch):
    """设置 TIER1_THREADS=8（多核调高）→ 解析为 8。"""
    _set_env(monkeypatch, "8")
    assert model._resolve_threads() == 8


def test_resolve_threads_clamps_to_minimum_1(monkeypatch):
    """非法/<1 的值兜底为 1（onnxruntime intra_op_num_threads 须 >=1，绝不让加载崩）。"""
    _set_env(monkeypatch, "0")
    assert model._resolve_threads() == 1


def test_resolve_threads_invalid_falls_back_to_default(monkeypatch):
    """非数字 → 回落默认 2，绝不抛异常（加载链 fail-safe）。"""
    _set_env(monkeypatch, "not-a-number")
    assert model._resolve_threads() == 2


def test_model_source_not_hardcoding_threads_literal():
    """回归守卫：model.py 不得再出现 intra_op_num_threads = <字面量数字>，
    必须经由 _resolve_threads() 读 env（防 FIX-3 被改回硬编码 2）。"""
    import re

    src = open(model.__file__, "r", encoding="utf-8").read()
    assert re.search(r"intra_op_num_threads\s*=\s*\d", src) is None, (
        "model.py 仍硬编码 intra_op_num_threads，应改为读 _resolve_threads()/env TIER1_THREADS"
    )
    assert "_resolve_threads" in src


def test_resolve_threads_follows_p1_tier_when_tier1_threads_is_blank(monkeypatch):
    """C4: blank TIER1_THREADS (compose ${TIER1_THREADS:-}) follows the P1 tier."""
    _set_env(monkeypatch, "")
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", "4")
    assert model._resolve_threads() == 4


def test_explicit_tier1_threads_wins_over_the_tier(monkeypatch):
    """An explicit operator value must never be overridden by autotune."""
    _set_env(monkeypatch, "8")
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", "4")
    assert model._resolve_threads() == 8


def test_blank_tier_falls_back_to_default_two(monkeypatch):
    _set_env(monkeypatch, "")
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", "")
    assert model._resolve_threads() == 2


def test_invalid_tier_value_does_not_break_loading(monkeypatch):
    _set_env(monkeypatch, "")
    monkeypatch.setenv("ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS", "many")
    assert model._resolve_threads() == 2
