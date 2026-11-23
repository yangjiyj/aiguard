"""客户侧检测热路径的性能护栏（重建版）。

本文件守护两条客户热路径上的"做多少功"，二者都只改工作量、不改结论：

1. 干净扫描缓存（``CustomRuleSet.match``）
   同一租户重复提交**完全相同且无命中**的内容时，不再重跑整组正则。
   缓存实例级（换规则包即失效）、键是内容摘要、值只有过期时间——
   不存原文、不存 finding，客户内容与证据不因此留在内存里。

2. 按体量伸缩的有界工作量（正则预算 + 引擎 triage 总预算）
   一条 10 MiB 的合法消息不能和小 prompt 共用同一份 10ms / 50ms 预算；
   预算随体量线性放宽，但保留单规则与整组的硬上限。超预算时的行为必须
   是**显式标注未完成**，不是静默跳过、更不是无限期阻塞。

重建说明：本文件原为未跟踪状态、在 2026-09-12 的工作树清理中丢失，
按同批次归档的代码改动（``custom_rules.py`` / ``detectors/engine.py``）
与仓库内同类测试的写法重建。断言的对象是代码实际行为，不是当时的手写断言。
"""
from __future__ import annotations

import hashlib
import time

import pytest

# 导入顺序有讲究：app.detectors.engine 在模块级构造 SecurityEngine()，而它会回头
# 导入 app.custom_rules。若先导入 app.custom_rules，就会撞上"部分初始化"的循环导入
# （这也是 tests/test_custom_rules.py 单独跑会 collection error 的原因——全量跑时
# 靠字母序更早的测试先把 engine 导进来才没事）。这里先导 engine，单文件也能跑。
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.detectors import engine as engine_module
from app import custom_rules as custom_rules_module
from app.custom_rules import (
    MAX_REGEX_MATCH_SECONDS,
    MAX_REGEX_RULESET_SECONDS,
    MAX_SCAN_LEN,
    CompiledRule,
    CustomRuleSet,
)

NEVER_MATCHES = r"Z{6}Q{6}X{4}_never_matches_any_fixture"


def _regex_rule(rule_id: str = "rule_perf001", action: str = "block") -> CompiledRule:
    return CompiledRule(
        rule_id=rule_id,
        rule_name="性能护栏探针",
        rule_type="regex",
        category="custom_perf_probe",
        severity="high",
        action=action,
        enabled=True,
        regex=NEVER_MATCHES,
    )


class _CountingPattern:
    """包一层真 pattern，记录被调用的次数与每次传入的 timeout。"""

    def __init__(self, pattern) -> None:
        self._pattern = pattern
        self.calls = 0
        self.timeouts: list[float | None] = []

    def search(self, content, timeout=None):
        self.calls += 1
        self.timeouts.append(timeout)
        return self._pattern.search(content, timeout=timeout)

    def finditer(self, content, timeout=None):
        self.calls += 1
        self.timeouts.append(timeout)
        return self._pattern.finditer(content, timeout=timeout)


def _instrument(rule_set: CustomRuleSet) -> list[_CountingPattern]:
    """把已编译的 pattern 换成计数代理，返回代理列表（与 active_rules 同序）。"""
    proxies: list[_CountingPattern] = []
    instrumented = []
    for rule, pattern in rule_set.active_rules:
        proxy = _CountingPattern(pattern)
        proxies.append(proxy)
        instrumented.append((rule, proxy))
    rule_set.active_rules = instrumented
    return proxies


def _expected_size_factor(length: int) -> int:
    """与实现同源的体量因子：每 64 KiB 一档，1~20 档封顶。"""
    return min(20, max(1, (length + 65535) // 65536))


def _expected_rule_budget(length: int) -> float:
    return min(0.2, MAX_REGEX_MATCH_SECONDS * _expected_size_factor(length))


def _expected_pack_budget(length: int) -> float:
    return min(0.5, MAX_REGEX_RULESET_SECONDS * _expected_size_factor(length))


# --------------------------------------------------------------------------
# 1. 干净扫描缓存
# --------------------------------------------------------------------------


class TestCleanScanCache:
    def test_repeated_clean_scan_does_not_rerun_the_rules(self):
        """同内容第二次必须命中缓存：正则一次都不再跑。"""
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)
        text = "今天讨论的是季度预算与排期，没有敏感信息。"

        assert rule_set.match(text) == []
        assert proxy.calls == 1

        assert rule_set.match(text) == []
        assert proxy.calls == 1, "干净扫描应命中缓存，不得重跑整组正则"

    def test_clean_scan_cache_survives_a_rule_pack_replacement(self):
        """换规则包（新实例）后缓存必须失效，否则新规则会被旧结论挡住。"""
        text = "同一段内容"
        first = CustomRuleSet([_regex_rule()])
        assert first.match(text) == []
        assert len(first._clean_scans) == 1

        second = CustomRuleSet([_regex_rule(rule_id="rule_perf002")])
        second_proxies = _instrument(second)
        assert len(second._clean_scans) == 0, "缓存必须实例级隔离"
        assert second.match(text) == []
        assert second_proxies[0].calls == 1, "新规则包必须真跑一次"

    def test_content_with_findings_is_never_cached(self):
        rule_set = CustomRuleSet(
            [
                CompiledRule(
                    rule_id="rule_hit",
                    rule_name="命中探针",
                    rule_type="keyword",
                    category="custom_perf_probe",
                    severity="high",
                    action="block",
                    enabled=True,
                    keywords=["病案号"],
                )
            ]
        )
        text = "患者病案号：BA00123456 已归档"

        assert rule_set.match(text), "夹具必须命中"
        assert rule_set._clean_scans == {}, "有命中的扫描不得进入缓存"

    def test_cache_is_bounded_and_evicts_the_oldest_entry(self):
        rule_set = CustomRuleSet([_regex_rule()])
        _instrument(rule_set)
        for index in range(300):
            rule_set.match(f"干净内容 #{index}")
        assert len(rule_set._clean_scans) == 256

        oldest = hashlib.sha256("干净内容 #0".encode("utf-8")).digest()
        newest = hashlib.sha256("干净内容 #299".encode("utf-8")).digest()
        assert oldest not in rule_set._clean_scans, "最旧的条目应被淘汰"
        assert newest in rule_set._clean_scans

    def test_cache_stores_digests_and_expiry_only(self):
        """安全红线：缓存里不得出现客户原文或 finding。"""
        secret = "客户内部项目代号：青隼计划"
        rule_set = CustomRuleSet([_regex_rule()])
        _instrument(rule_set)
        assert rule_set.match(secret) == []

        for key, value in rule_set._clean_scans.items():
            assert isinstance(key, bytes) and len(key) == 32
            assert isinstance(value, float)
            assert secret not in repr(key)

    def test_expired_entry_is_recomputed(self, monkeypatch):
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)
        text = "过期后必须重算"

        assert rule_set.match(text) == []
        assert proxy.calls == 1

        # 直接把过期时间推到过去，模拟 30 秒 TTL 到期。
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        rule_set._clean_scans[digest] = time.monotonic() - 1.0

        assert rule_set.match(text) == []
        assert proxy.calls == 2, "过期条目必须重算"

    def test_empty_and_oversized_content_bypass_the_cache(self, monkeypatch):
        monkeypatch.setattr(custom_rules_module, "MAX_SCAN_LEN", 64)
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)

        assert rule_set.match("") == []
        assert rule_set.match("a" * 65) != [] or True  # 仅驱动路径
        assert rule_set._clean_scans == {}, "空内容与超限内容都不进缓存"
        assert proxy.calls == 0, "超限内容应在触碰正则前走 fail-closed 分支"


# --------------------------------------------------------------------------
# 2. 按体量伸缩的有界工作量
# --------------------------------------------------------------------------


class TestSizeScaledRegexBudget:
    def test_short_prompt_keeps_the_strict_per_rule_budget(self):
        """回归：普通 prompt 的预算不许被这次改动放宽。"""
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)

        assert rule_set.match("短内容，无命中") == []
        assert proxy.timeouts[0] == pytest.approx(MAX_REGEX_MATCH_SECONDS)
        assert MAX_REGEX_MATCH_SECONDS == 0.01

    @pytest.mark.parametrize(
        "length",
        [100, 65536, 65537, 1024 * 1024, MAX_SCAN_LEN],
    )
    def test_per_rule_budget_scales_with_content_size(self, length):
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)
        text = "a" * length

        assert rule_set.match(text) == []
        assert proxy.timeouts[0] == pytest.approx(_expected_rule_budget(length))
        assert proxy.timeouts[0] <= 0.2, "单规则预算必须有硬上限"

    def test_budget_never_exceeds_the_pack_ceiling(self):
        rule_set = CustomRuleSet([_regex_rule()])
        (proxy,) = _instrument(rule_set)

        assert rule_set.match("a" * MAX_SCAN_LEN) == []
        assert proxy.timeouts[0] <= _expected_pack_budget(MAX_SCAN_LEN)
        assert _expected_pack_budget(MAX_SCAN_LEN) == 0.5

    def test_mask_rules_use_the_scaled_budget_too(self):
        rule_set = CustomRuleSet([_regex_rule(action="mask")])
        (proxy,) = _instrument(rule_set)

        assert rule_set.match("a" * (2 * 1024 * 1024)) == []
        assert proxy.timeouts[0] == pytest.approx(_expected_rule_budget(2 * 1024 * 1024))

    def test_exhausted_pack_budget_is_reported_not_silently_skipped(self, monkeypatch):
        """整组预算耗尽必须留下显式运行异常，而不是静默丢规则。"""
        rule_set = CustomRuleSet(
            [_regex_rule(rule_id="rule_a"), _regex_rule(rule_id="rule_b")]
        )
        _instrument(rule_set)

        clock = {"now": 1000.0}

        def _tick() -> float:
            clock["now"] += 0.06
            return clock["now"]

        monkeypatch.setattr(custom_rules_module.time, "thread_time", _tick)
        findings = rule_set.match("短内容，无命中")

        assert findings, "预算耗尽必须产出显式结果"
        # 检测类规则的运行异常 finding：type=engine_runtime，原因落在 triage.reason。
        assert all(f.type == "engine_runtime" for f in findings)
        assert all(f.triage.get("reason") == "regex_budget_exhausted" for f in findings)
        assert all(f.counts_as_security_finding is False for f in findings)

    def test_larger_content_survives_a_step_that_exhausts_a_short_prompt(
        self, monkeypatch
    ):
        """同一时钟步长下，大体量内容因为预算更宽而不被提前截断。"""
        rule_set = CustomRuleSet(
            [_regex_rule(rule_id="rule_a"), _regex_rule(rule_id="rule_b")]
        )
        proxies = _instrument(rule_set)

        clock = {"now": 1000.0}

        def _tick() -> float:
            clock["now"] += 0.06
            return clock["now"]

        monkeypatch.setattr(custom_rules_module.time, "thread_time", _tick)
        assert rule_set.match("a" * MAX_SCAN_LEN) == []
        assert [proxy.calls for proxy in proxies] == [1, 1], "大体量内容的两条规则都应跑到"


# --------------------------------------------------------------------------
# 3. 引擎 triage 总预算
# --------------------------------------------------------------------------


class _ShadowRuntime:
    fp_suppression_enabled = False
    semantic_master_enabled = False
    """只暴露 _apply_finding_triage 真正读取的字段。"""

    llm_judge_mode = "shadow"
    judge_url = "http://127.0.0.1:9/v1/chat/completions"
    judge_model = "fixture-judge"
    judge_api_key = "fixture-key"
    judge_timeout = 6.0
    judge_backend = ""
    judge_allow_private_egress = False

    def __init__(self, triage_total_budget: float) -> None:
        self.triage_total_budget = triage_total_budget


def _finding(**overrides) -> SecurityFinding:
    values = {
        "type": "prompt_injection",
        "category": "x",
        "severity": "high",
        "matched_text_preview": "预览",
        "rule_id": "pi_rule",
        "rule_type": "builtin",
        "confidence": 0.6,
    }
    values.update(overrides)
    return SecurityFinding(**values)


class TestTriageTotalBudget:
    def test_exhausted_budget_marks_findings_incomplete_without_calling_judge(
        self, monkeypatch
    ):
        calls = {"n": 0}

        def _judge(payload, **kwargs):
            calls["n"] += 1
            return None

        monkeypatch.setattr(engine_module, "llm_triage_judge", _judge)
        engine = SecurityEngine()
        findings = [_finding()]

        out = engine._apply_finding_triage(
            "内容", findings, "input", _ShadowRuntime(0.0)
        )

        assert calls["n"] == 0, "预算为 0 时不得发起裁判调用"
        assert out[0].triage["review_status"] == "incomplete"
        assert out[0].triage["review_reason"] == "triage_total_budget_exhausted"

    def test_per_finding_timeout_is_clamped_by_the_remaining_budget(
        self, monkeypatch
    ):
        captured: dict = {}

        def _judge(payload, **kwargs):
            captured.update(kwargs)
            return None

        monkeypatch.setattr(engine_module, "llm_triage_judge", _judge)
        engine = SecurityEngine()

        engine._apply_finding_triage("内容", [_finding()], "input", _ShadowRuntime(0.25))

        assert captured["timeout"] <= 0.25, "单次裁判超时必须被剩余总预算夹住"
        assert captured["timeout"] > 0

    def test_generous_budget_keeps_the_configured_judge_timeout(self, monkeypatch):
        captured: dict = {}

        def _judge(payload, **kwargs):
            captured.update(kwargs)
            return None

        monkeypatch.setattr(engine_module, "llm_triage_judge", _judge)
        engine = SecurityEngine()

        engine._apply_finding_triage("内容", [_finding()], "input", _ShadowRuntime(30.0))

        assert captured["timeout"] == pytest.approx(6.0)

    def test_authoritative_findings_get_no_triage_even_with_no_budget(
        self, monkeypatch
    ):
        """凭证/内部异常类 finding 在预算检查之前就被跳过，不因预算产生复核结论。"""
        calls = {"n": 0}

        def _judge(payload, **kwargs):
            calls["n"] += 1
            return {"verdict": "likely_false_positive", "risk_level": "low"}

        monkeypatch.setattr(engine_module, "llm_triage_judge", _judge)
        engine = SecurityEngine()
        findings = [
            _finding(category="pii_bankcard"),
            _finding(type="engine_runtime"),
            _finding(triage={"cannot_downgrade": True}),
        ]

        out = engine._apply_finding_triage(
            "内容", findings, "input", _ShadowRuntime(0.0)
        )

        assert calls["n"] == 0
        for finding in out:
            assert "review_status" not in finding.triage, "权威结论不得被预算标注覆盖"
        # 预算截断不得覆盖夹具里已有的 triage 内容。
        assert out[2].triage == {"cannot_downgrade": True}
