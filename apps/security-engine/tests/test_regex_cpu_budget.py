"""正则预算按本线程 CPU 时间记账：等 GIL 不耗预算，真慢仍被掐断。

全部用假时钟 / 假 pattern 模拟，不依赖真实计时抖动。
"""
import dataclasses
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.detectors.engine import SecurityEngine  # noqa: F401  (先于 custom_rules 导入，避免循环导入)
from app import custom_rules, regex_budget
from app.custom_rules import CompiledRule, CustomRuleSet
from app.detectors import policy_catalog as catalog


class FakeCpuClock:
    """可控的 thread_time；fake pattern 通过 burn() 推进。"""

    def __init__(self, monkeypatch):
        self.now = 1000.0
        monkeypatch.setattr(time, "thread_time", lambda: self.now)

    def burn(self, seconds):
        self.now += seconds


def _rule(rule_id="r1", action="audit", pattern="ZZHIT"):
    return CompiledRule(
        rule_id=rule_id, rule_name=rule_id, rule_type="regex", category="custom_cpu",
        severity="high", action=action, regex=pattern,
    )


def _install(monkeypatch, patterns):
    """让每条规则编译为指定的假 pattern（按 rule 顺序）。"""
    it = iter(patterns)
    monkeypatch.setattr(custom_rules, "validate_and_compile_regex", lambda _p: (next(it), None))


class ScriptedPattern:
    """按脚本依次行动：('timeout', cpu_burn) 抛 TimeoutError；('ok', cpu_burn) 返回 result。"""

    def __init__(self, clock, script, result=None):
        self.clock, self.script, self.result = clock, list(script), result
        self.timeouts = []

    def search(self, _content, *, timeout):
        self.timeouts.append(timeout)
        kind, burn = self.script.pop(0)
        self.clock.burn(burn)
        if kind == "timeout":
            raise TimeoutError("simulated")
        return self.result


# ---------------------------------------------------------------- custom_rules

def test_wall_timeout_with_little_cpu_retries_and_succeeds(monkeypatch, caplog):
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.001), ("ok", 0.001)])
    _install(monkeypatch, [pattern])
    ruleset = CustomRuleSet([_rule()])
    with caplog.at_level(logging.WARNING, logger="app.custom_rules"):
        findings = ruleset.match("payload")
    assert findings == []
    assert not ruleset.runtime_failure_counts
    assert "regex runtime failure" not in caplog.text
    first, retry = pattern.timeouts
    assert first == pytest.approx(custom_rules.MAX_REGEX_MATCH_SECONDS)
    # 剩余 CPU 预算 = 0.01 - 0.001；墙钟 = 剩余 x 10
    assert retry == pytest.approx(0.009 * 10)


def test_cpu_exhausted_timeout_is_still_regex_timeout_without_retry(monkeypatch, caplog):
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.0095)])  # >= 80% 预算：真慢
    _install(monkeypatch, [pattern])
    ruleset = CustomRuleSet([_rule("slow")])
    with caplog.at_level(logging.WARNING, logger="app.custom_rules"):
        findings = ruleset.match("payload")
    assert ruleset.runtime_failure_counts[("slow", "regex_timeout")] == 1
    assert findings[0].category == "engine_scan_incomplete"
    assert len(pattern.timeouts) == 1
    assert "retried=0" in caplog.text


def test_retry_that_still_times_out_records_regex_timeout(monkeypatch, caplog):
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.001), ("timeout", 0.5)])
    _install(monkeypatch, [pattern])
    ruleset = CustomRuleSet([_rule("slow")])
    with caplog.at_level(logging.WARNING, logger="app.custom_rules"):
        ruleset.match("payload")
    assert ruleset.runtime_failure_counts[("slow", "regex_timeout")] == 1
    assert len(pattern.timeouts) == 2
    assert "retried=1" in caplog.text


def test_retry_wall_timeout_is_capped_by_wall_max(monkeypatch):
    monkeypatch.setenv("SECURITY_REGEX_WALL_MAX_SECONDS", "0.05")
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.0), ("ok", 0.0)])
    _install(monkeypatch, [pattern])
    CustomRuleSet([_rule()]).match("payload")
    assert pattern.timeouts[1] == pytest.approx(0.05)


def test_retry_wall_slack_env(monkeypatch):
    monkeypatch.setenv("SECURITY_REGEX_WALL_SLACK", "3")
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.002), ("ok", 0.0)])
    _install(monkeypatch, [pattern])
    CustomRuleSet([_rule()]).match("payload")
    assert pattern.timeouts[1] == pytest.approx(0.008 * 3)


def test_failure_log_keeps_old_fields_and_appends_new(monkeypatch, caplog):
    clock = FakeCpuClock(monkeypatch)
    pattern = ScriptedPattern(clock, [("timeout", 0.0095)])
    _install(monkeypatch, [pattern])
    with caplog.at_level(logging.WARNING, logger="app.custom_rules"):
        CustomRuleSet([_rule("slow", action="block")]).match("payload")
    line = next(r.getMessage() for r in caplog.records if "regex runtime failure" in r.getMessage())
    assert line.startswith("regex runtime failure rule_id=slow reason=regex_timeout count=1 action=block ")
    assert line.endswith("retried=0")
    assert " cpu_ms=9.5 wall_ms=" in line


def test_budget_exhausted_is_judged_by_cpu_time(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    monkeypatch.setattr(custom_rules, "MAX_REGEX_RULESET_SECONDS", 0.05)
    monkeypatch.setattr(custom_rules, "MAX_REGEX_MATCH_SECONDS", 0.05)
    first = ScriptedPattern(clock, [("ok", 0.06)])   # 一条就吃光整包 CPU 预算
    second = ScriptedPattern(clock, [("ok", 0.0)])
    _install(monkeypatch, [first, second])
    ruleset = CustomRuleSet([_rule("a"), _rule("b")])
    ruleset.match("payload")
    assert ruleset.runtime_failure_counts[("b", "regex_budget_exhausted")] == 1
    assert second.timeouts == []


def test_waiting_for_gil_does_not_exhaust_pack_budget(monkeypatch):
    """墙钟已远超整包预算、但本线程 CPU 几乎没动：后续规则照常执行。"""
    FakeCpuClock(monkeypatch)  # CPU 时钟不动
    monkeypatch.setattr(custom_rules, "MAX_REGEX_RULESET_SECONDS", 0.01)

    class WallSlow:
        def __init__(self):
            self.calls = 0

        def search(self, _content, *, timeout):
            self.calls += 1
            time.sleep(0.03)  # 模拟等锁：墙钟流逝，CPU 不变
            return None

    a, b = WallSlow(), WallSlow()
    _install(monkeypatch, [a, b])
    ruleset = CustomRuleSet([_rule("a"), _rule("b")])
    ruleset.match("payload")
    assert not ruleset.runtime_failure_counts
    assert (a.calls, b.calls) == (1, 1)


def _child_env(**extra):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    env.update({
        "CONTROL_PLANE_URL": "", "JJD_INTERNAL_API_SECRET": "",
        "SECURITY_LLM_JUDGE_MODE": "off", "SECURITY_SEMANTIC_ENABLED": "false",
        "SECURITY_TIER1_ENABLED": "false",
    })
    env.update(extra)
    return env


_PRINT_CONSTANTS = """
import json
from app.detectors.engine import SecurityEngine
from app import custom_rules as c
from app.detectors import policy_catalog as p
print(json.dumps([c.MAX_REGEX_MATCH_SECONDS, c.MAX_REGEX_RULESET_SECONDS,
    c.MAX_REGEX_MATCH_CEILING_SECONDS, c.MAX_REGEX_RULESET_CEILING_SECONDS,
    p._CATALOG_BUDGET_SECONDS, p._CATALOG_REGEX_TIMEOUT_SECONDS]))
"""


def _constants(**env):
    out = subprocess.run([sys.executable, "-c", _PRINT_CONSTANTS], capture_output=True, text=True,
                         env=_child_env(**env), timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.splitlines()[-1]), out.stderr


def test_defaults_unchanged():
    values, _ = _constants()
    assert values == [0.01, 0.05, 0.2, 0.5, 2.0, 0.25]


def test_env_overrides_apply():
    values, _ = _constants(
        SECURITY_CUSTOM_REGEX_RULE_SECONDS="0.02", SECURITY_CUSTOM_REGEX_PACK_SECONDS="0.1",
        SECURITY_CUSTOM_REGEX_RULE_MAX_SECONDS="0.3", SECURITY_CUSTOM_REGEX_PACK_MAX_SECONDS="0.8",
        SECURITY_CATALOG_BUDGET_SECONDS="3", SECURITY_CATALOG_REGEX_TIMEOUT_SECONDS="0.5",
    )
    assert values == [0.02, 0.1, 0.3, 0.8, 3.0, 0.5]


def test_invalid_env_falls_back_to_defaults_with_warning():
    values, stderr = _constants(
        SECURITY_CUSTOM_REGEX_RULE_SECONDS="abc", SECURITY_CUSTOM_REGEX_PACK_SECONDS="-1",
        SECURITY_CUSTOM_REGEX_RULE_MAX_SECONDS="nan", SECURITY_CUSTOM_REGEX_PACK_MAX_SECONDS="9999",
        SECURITY_CATALOG_BUDGET_SECONDS="0", SECURITY_CATALOG_REGEX_TIMEOUT_SECONDS="inf",
    )
    assert values == [0.01, 0.05, 0.2, 0.5, 2.0, 0.25]
    assert "SECURITY_CUSTOM_REGEX_RULE_SECONDS" in stderr


@pytest.mark.parametrize("value", ["abc", "0", "-3", "1000", "nan", ""])
def test_wall_slack_and_wall_max_fall_back(monkeypatch, value):
    monkeypatch.setenv("SECURITY_REGEX_WALL_SLACK", value)
    monkeypatch.setenv("SECURITY_REGEX_WALL_MAX_SECONDS", value)
    assert regex_budget.wall_slack() == 10.0
    assert regex_budget.wall_max_seconds() == 2.0


def test_env_float_warns_on_invalid(monkeypatch, caplog):
    monkeypatch.setenv("X_TEST_BUDGET", "oops")
    with caplog.at_level(logging.WARNING, logger="app.regex_budget"):
        assert regex_budget.env_float("X_TEST_BUDGET", 1.5, 0.1, 9) == 1.5
    assert "X_TEST_BUDGET" in caplog.text


# --------------------------------------------------------------------- catalog

def _catalog_rule(required):
    base = next(r for r in catalog.POLICY_CATALOG_RULES if r.category == "injection_comparison_pretext")
    return dataclasses.replace(base, required=tuple(required))


def _gap(findings):
    return [f for f in findings if f["category"] == "engine_scan_incomplete"]


class CatalogSearch:
    def __init__(self, clock, script, result=None):
        self.clock, self.script, self.result = clock, list(script), result
        self.options = []

    def search(self, _text, **options):
        self.options.append(options)
        kind, burn = self.script.pop(0)
        self.clock.burn(burn)
        if kind == "timeout":
            raise TimeoutError("simulated")
        return self.result


def test_catalog_wall_timeout_with_little_cpu_retries(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    pattern = CatalogSearch(clock, [("timeout", 0.001), ("ok", 0.001)])
    monkeypatch.setattr(catalog, "POLICY_CATALOG_RULES", (_catalog_rule([pattern]),))
    findings = catalog.PolicyCatalogDetector().detect("synthetic", "input")
    assert findings == []
    assert len(pattern.options) == 2
    assert pattern.options[0]["timeout"] == pytest.approx(catalog._CATALOG_REGEX_TIMEOUT_SECONDS)
    # 剩余 0.249s x 10 = 2.49s，被 SECURITY_REGEX_WALL_MAX_SECONDS(2.0) 封顶
    assert pattern.options[1]["timeout"] == pytest.approx(2.0)
    assert pattern.options[1]["concurrent"] is True


def test_catalog_cpu_exhausted_timeout_reports_regex_timeout(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    pattern = CatalogSearch(clock, [("timeout", 0.24)])  # >= 80% x 0.25
    monkeypatch.setattr(catalog, "POLICY_CATALOG_RULES", (_catalog_rule([pattern]),))
    findings = catalog.PolicyCatalogDetector().detect("synthetic", "input")
    assert _gap(findings)[0]["triage"]["review_reason"] == "catalog_regex_timeout"
    assert len(pattern.options) == 1


def test_catalog_retry_still_timing_out_reports_regex_timeout(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    pattern = CatalogSearch(clock, [("timeout", 0.001), ("timeout", 0.2)])
    monkeypatch.setattr(catalog, "POLICY_CATALOG_RULES", (_catalog_rule([pattern]),))
    findings = catalog.PolicyCatalogDetector().detect("synthetic", "input")
    assert _gap(findings)[0]["triage"]["review_reason"] == "catalog_regex_timeout"
    assert len(pattern.options) == 2


def test_catalog_budget_exhausted_by_cpu_not_wall(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    first = CatalogSearch(clock, [("ok", 2.01)], result=object())  # 一次调用吃光 2s CPU 预算
    monkeypatch.setattr(catalog, "POLICY_CATALOG_RULES", (_catalog_rule([first]),))
    findings = catalog.PolicyCatalogDetector().detect("synthetic", "input")
    assert _gap(findings)[0]["triage"]["review_reason"] == "catalog_budget_exhausted"


def test_catalog_waiting_for_gil_does_not_exhaust_budget(monkeypatch):
    FakeCpuClock(monkeypatch)
    monkeypatch.setattr(catalog, "_CATALOG_BUDGET_SECONDS", 0.01)

    class WallSlow:
        def search(self, _text, **options):
            time.sleep(0.03)
            return None

    monkeypatch.setattr(catalog, "POLICY_CATALOG_RULES", (_catalog_rule([WallSlow()]),))
    assert catalog.PolicyCatalogDetector().detect("synthetic", "input") == []


def test_catalog_finditer_timeout_resumes_after_last_match(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    import regex

    real = regex.compile("x")
    text = "x..x..x"

    class Flaky:
        def __init__(self):
            self.calls = []

        def search(self, content, **options):
            return real.search(content)

        def finditer(self, content, **options):
            self.calls.append(dict(options))
            first = len(self.calls) == 1

            def gen():
                for m in real.finditer(content, pos=options.get("pos", 0)):
                    yield m
                    if first:
                        clock.burn(0.001)
                        raise TimeoutError("simulated")
            return gen()

    flaky = Flaky()
    spans = [(m.start(), m.end()) for m in catalog._catalog_finditer(flaky, text, time.monotonic() + 60)]
    assert spans == [(0, 1), (3, 4), (6, 7)]
    assert flaky.calls[0].get("pos") is None
    assert flaky.calls[1]["pos"] == 1


# ------------------------------------------------- 整包墙钟上限 / 熔断 / catalog 兜底

class FakeWallClock:
    def __init__(self, monkeypatch):
        self.now = 5000.0
        monkeypatch.setattr(time, "monotonic", lambda: self.now)

    def advance(self, seconds):
        self.now += seconds


class WallBurner:
    """search 时推进墙钟（模拟等锁），CPU 不变。"""

    def __init__(self, wall, advance):
        self.wall, self.advance, self.calls = wall, advance, 0

    def search(self, _content, *, timeout):
        self.calls += 1
        self.wall.advance(self.advance)
        return None


def test_pack_wall_cap_marks_unrun_rules_budget_exhausted(monkeypatch):
    FakeCpuClock(monkeypatch)
    wall = FakeWallClock(monkeypatch)
    first, second = WallBurner(wall, 3.5), WallBurner(wall, 0)
    _install(monkeypatch, [first, second])
    ruleset = CustomRuleSet([_rule("a"), _rule("b")])
    ruleset.match("payload")
    assert first.calls == 1  # 已在跑的不被打断
    assert second.calls == 0
    assert ruleset.runtime_failure_counts[("b", "regex_budget_exhausted")] == 1
    assert ("a", "regex_budget_exhausted") not in ruleset.runtime_failure_counts


def test_pack_wall_cap_env_override_and_invalid_fallback(monkeypatch):
    FakeCpuClock(monkeypatch)
    wall = FakeWallClock(monkeypatch)
    monkeypatch.setenv("SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS", "0.5")
    a, b = WallBurner(wall, 0.6), WallBurner(wall, 0)
    _install(monkeypatch, [a, b])
    rs = CustomRuleSet([_rule("a"), _rule("b")])
    rs.match("x")
    assert rs.runtime_failure_counts[("b", "regex_budget_exhausted")] == 1
    # 非法值回落默认 3.0：0.6s 不触顶
    monkeypatch.setenv("SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS", "0.01")
    a, b = WallBurner(wall, 0.6), WallBurner(wall, 0)
    _install(monkeypatch, [a, b])
    rs = CustomRuleSet([_rule("a"), _rule("b")])
    rs.match("y")
    assert not rs.runtime_failure_counts and b.calls == 1


def test_pack_wall_cap_default_allows_under_three_seconds(monkeypatch):
    FakeCpuClock(monkeypatch)
    wall = FakeWallClock(monkeypatch)
    a, b = WallBurner(wall, 2.9), WallBurner(wall, 0)
    _install(monkeypatch, [a, b])
    rs = CustomRuleSet([_rule("a"), _rule("b")])
    rs.match("z")
    assert not rs.runtime_failure_counts and b.calls == 1


def test_circuit_breaker_stops_retries_after_failed_retry(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    a = ScriptedPattern(clock, [("timeout", 0.001), ("timeout", 0.001)])
    b = ScriptedPattern(clock, [("timeout", 0.001), ("ok", 0.0)])
    c = ScriptedPattern(clock, [("ok", 0.0)])
    _install(monkeypatch, [a, b, c])
    rs = CustomRuleSet([_rule("a"), _rule("b"), _rule("c")])
    rs.match("payload")
    assert len(a.timeouts) == 2
    assert len(b.timeouts) == 1  # 熔断：b 不再重试
    assert rs.runtime_failure_counts[("a", "regex_timeout")] == 1
    assert rs.runtime_failure_counts[("b", "regex_timeout")] == 1
    assert len(c.timeouts) == 1 and ("c", "regex_timeout") not in rs.runtime_failure_counts


def test_circuit_breaker_not_tripped_by_successful_retry(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    a = ScriptedPattern(clock, [("timeout", 0.001), ("ok", 0.0)])
    b = ScriptedPattern(clock, [("timeout", 0.001), ("ok", 0.0)])
    _install(monkeypatch, [a, b])
    rs = CustomRuleSet([_rule("a"), _rule("b")])
    rs.match("payload")
    assert len(b.timeouts) == 2 and not rs.runtime_failure_counts


def test_circuit_breaker_is_per_match_call(monkeypatch):
    clock = FakeCpuClock(monkeypatch)
    a = ScriptedPattern(clock, [("timeout", 0.001), ("timeout", 0.001), ("timeout", 0.001), ("ok", 0.0)])
    _install(monkeypatch, [a])
    rs = CustomRuleSet([_rule("a")])
    rs.match("one")
    rs.match("two")
    assert len(a.timeouts) == 4  # 第二次 match 重新允许重试


def test_catalog_wall_fallback_is_budget_plus_wall_max(monkeypatch):
    wall = FakeWallClock(monkeypatch)
    assert catalog._catalog_deadline() == pytest.approx(wall.now + 2.0 + 2.0)
    monkeypatch.setenv("SECURITY_REGEX_WALL_MAX_SECONDS", "1")
    assert catalog._catalog_deadline() == pytest.approx(wall.now + 2.0 + 1.0)


def test_catalog_wall_fallback_still_capped_by_parent_budget(monkeypatch):
    from app.bounded_work import execution_budget
    wall = FakeWallClock(monkeypatch)
    with execution_budget(wall.now + 0.5):
        assert catalog._catalog_deadline() == pytest.approx(wall.now + 0.5)


# ------------------------------------------- 真实 regex + 真实 GIL 争抢（不用假时钟/假 pattern）

import sys  # noqa: E402
import threading  # noqa: E402

import regex as _real_regex  # noqa: E402


@pytest.fixture
def gil_contention():
    """启动 N 个纯 Python 忙线程制造 GIL 争抢，测试结束后停掉。"""
    stop = threading.Event()
    threads = []
    old_interval = sys.getswitchinterval()

    def start(count, switch_interval=None):
        if switch_interval is not None:
            sys.setswitchinterval(switch_interval)
        def busy():
            x = 0
            while not stop.is_set():
                x += 1
        for _ in range(count):
            t = threading.Thread(target=busy, daemon=True)
            t.start()
            threads.append(t)

    yield start
    stop.set()
    sys.setswitchinterval(old_interval)
    for t in threads:
        t.join(timeout=5)


def _compile_real(monkeypatch):
    # 准入启发式会拒绝嵌套量词；这里只验证运行时预算，直接编译真实 regex。
    monkeypatch.setattr(
        custom_rules, "validate_and_compile_regex",
        lambda p: (_real_regex.compile(p), None),
    )


def test_real_regex_hit_survives_gil_contention_via_retry(monkeypatch, gil_contention):
    _compile_real(monkeypatch)
    monkeypatch.setenv("SECURITY_REGEX_WALL_SLACK", "100")
    monkeypatch.setenv("SECURITY_REGEX_WALL_MAX_SECONDS", "5")
    monkeypatch.setenv("SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS", "30")
    monkeypatch.setattr(custom_rules, "MAX_REGEX_MATCH_SECONDS", 0.01)
    monkeypatch.setattr(custom_rules, "MAX_REGEX_RULESET_SECONDS", 0.5)
    filler = "The quick brown fox jumps over the lazy dog, order 12345 shipped. "
    base = (filler * 800)[:40000]
    rule = _rule("hit", action="audit", pattern=r"(?<!\d)1[3-9]\d{9}(?!\d)")

    def run(tag):
        return [
            (f.rule_id, f.type)
            for f in CustomRuleSet([rule]).match(f"{base} {tag} call 13812345678 tail")
        ]

    quiet = run("quiet")
    assert quiet == [("hit", "custom")]

    retries = []
    real_run = regex_budget.run_with_cpu_budget
    # 真实 regex，仅第一次调用把墙钟 timeout 压到 1 微秒，由 regex 库真实抛出
    # TimeoutError（CPU 几乎为 0），使"首次墙钟超时 -> 重试"路径必然发生；
    # 重试沿用调用方给的真实墙钟 timeout，在真实 GIL 争抢下执行。
    real_pattern = _real_regex.compile(rule.regex)

    class FirstCallTimesOut:
        calls = 0

        def search(self, content, *, timeout):
            FirstCallTimesOut.calls += 1
            if FirstCallTimesOut.calls % 2 == 1:
                timeout = 1e-9
            return real_pattern.search(content, timeout=timeout)

    proxy = FirstCallTimesOut()
    monkeypatch.setattr(
        custom_rules, "validate_and_compile_regex", lambda p: (proxy, None)
    )

    def spy(fn, cpu_budget, stats, allow_retry=True):
        try:
            return real_run(fn, cpu_budget, stats, allow_retry)
        finally:
            retries.append(stats.retried)

    monkeypatch.setattr(custom_rules, "run_with_cpu_budget", spy)
    # 缩短 GIL 切换间隔，让争抢真实存在但耗时可预期，避免用例偶发。
    gil_contention(4, switch_interval=0.0005)
    for i in range(5):
        assert run(f"busy{i}") == quiet
    assert any(retries), "争抢下应至少触发过一次首次墙钟超时后的重试"


def test_real_catastrophic_regex_is_bounded_and_reported_under_contention(
    monkeypatch, gil_contention
):
    _compile_real(monkeypatch)
    pack_wall_max = 3.0  # 默认值
    gil_contention(4)
    rule = _rule("redos", action="block", pattern=r"(a|a)+$")
    ruleset = CustomRuleSet([rule])
    started = time.monotonic()
    findings = ruleset.match("a" * 30 + "b")
    elapsed = time.monotonic() - started
    assert elapsed <= pack_wall_max + 0.5, f"单次 match 墙钟 {elapsed:.2f}s"
    counts = ruleset.runtime_failure_counts
    assert (
        counts.get(("redos", "regex_timeout"), 0)
        + counts.get(("redos", "regex_budget_exhausted"), 0)
    ) == 1, "不能静默无命中，必须记运行异常"
    assert len(findings) == 1 and findings[0].category == "engine_scan_incomplete"
