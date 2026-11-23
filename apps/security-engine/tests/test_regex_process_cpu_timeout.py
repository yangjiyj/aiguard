"""regex 库的 timeout 按 clock()（整进程 CPU）计时，而预算按本线程 CPU 记账。

现场（2.9.15）内置 block/mask 规则 regex_timeout 时本线程 cpu_ms 只有 0.1~0.7、
wall_ms≈10：同进程其它线程并行消耗的 CPU 把 10ms 的 regex timeout 吃掉了。
这里固定两件事：
1. 重试的 timeout 必须按实测「进程 CPU / 本线程 CPU」倍率换算，让本线程真正拿到剩余预算；
   真慢（本线程 CPU 耗尽预算）仍按原样掐断，总墙钟仍受 WALL_MAX 封顶。
2. 整包预算紧张时，block/mask 规则先于 audit 规则执行；输出顺序保持规则包原序。
"""
import hashlib
import os
import threading
import time

import pytest
import regex as real_regex

from app.detectors.engine import SecurityEngine  # noqa: F401  (先于 custom_rules 导入，避免循环导入)
from app import custom_rules, regex_budget
from app.custom_rules import CompiledRule, CustomRuleSet


class FakeClocks:
    """thread_time / process_time 双假时钟：thread 为本线程 CPU，process 为整进程 CPU。"""

    def __init__(self, monkeypatch):
        self.thread = 1000.0
        self.process = 5000.0
        monkeypatch.setattr(time, "thread_time", lambda: self.thread)
        monkeypatch.setattr(time, "process_time", lambda: self.process)

    def run(self, own, contention):
        """本线程耗 own 秒 CPU；同期整进程耗 own*contention 秒。"""
        self.thread += own
        self.process += own * contention


class ContendedPattern:
    """按 regex 真实语义建模：timeout 以整进程 CPU 计；同进程倍率稳定为 contention。

    本线程需要 need 秒 CPU 才能扫完。整进程 CPU 先到 timeout 就抛 TimeoutError。
    """

    def __init__(self, clocks, need, contention, result=None):
        self.clocks, self.need, self.contention, self.result = clocks, need, contention, result
        self.timeouts = []

    def search(self, _content, *, timeout):
        self.timeouts.append(timeout)
        if self.need * self.contention <= timeout:
            self.clocks.run(self.need, self.contention)
            return self.result
        self.clocks.run(timeout / self.contention, self.contention)
        raise TimeoutError("regex timed out")


class Hit:
    def __init__(self, text="ZZHIT"):
        self._text = text

    def groupdict(self):
        return {}

    def groups(self):
        return ()

    def group(self, _index=0):
        return self._text

    def span(self, _index=0):
        return (0, len(self._text))


def _rule(rule_id, action="audit"):
    return CompiledRule(
        rule_id=rule_id, rule_name=rule_id, rule_type="regex", category="custom_cpu",
        severity="high", action=action, regex="ZZHIT",
    )


def _install(monkeypatch, patterns):
    it = iter(patterns)
    monkeypatch.setattr(custom_rules, "validate_and_compile_regex", lambda _p: (next(it), None))


def test_retry_timeout_scales_with_measured_process_cpu_contention(monkeypatch):
    """本线程只需 2ms（预算 10ms 内），但进程 CPU 是本线程的 100 倍：必须扫完并命中。"""
    clocks = FakeClocks(monkeypatch)
    pattern = ContendedPattern(clocks, need=0.002, contention=100.0, result=Hit())
    _install(monkeypatch, [pattern])
    ruleset = CustomRuleSet([_rule("passport_like", action="block")])
    findings = ruleset.match("payload")
    assert not ruleset.runtime_failure_counts
    assert [(f.rule_id, f.type) for f in findings] == [("passport_like", "custom")]
    assert len(pattern.timeouts) == 2
    # 首次仍等于本线程预算（空闲时行为不变）
    assert pattern.timeouts[0] == pytest.approx(custom_rules.MAX_REGEX_MATCH_SECONDS)


def test_retry_timeout_still_capped_by_wall_max_under_contention(monkeypatch):
    monkeypatch.setenv("SECURITY_REGEX_WALL_MAX_SECONDS", "0.05")
    clocks = FakeClocks(monkeypatch)
    pattern = ContendedPattern(clocks, need=0.002, contention=100.0, result=Hit())
    _install(monkeypatch, [pattern])
    ruleset = CustomRuleSet([_rule("capped")])
    ruleset.match("payload")
    assert pattern.timeouts[1] == pytest.approx(0.05)
    assert ruleset.runtime_failure_counts[("capped", "regex_timeout")] == 1


def test_genuinely_slow_regex_is_still_cut_within_own_cpu_budget(monkeypatch):
    """本线程需要 20ms > 10ms 预算：即使有争用倍率放大，也必须超时并记账，本线程 CPU 不超预算。"""
    clocks = FakeClocks(monkeypatch)
    pattern = ContendedPattern(clocks, need=0.02, contention=100.0, result=Hit())
    _install(monkeypatch, [pattern])
    thread_before = clocks.thread
    ruleset = CustomRuleSet([_rule("slow", action="block")])
    findings = ruleset.match("payload")
    assert ruleset.runtime_failure_counts[("slow", "regex_timeout")] == 1
    assert findings[0].type == "engine_runtime"
    own = clocks.thread - thread_before
    assert own <= custom_rules.MAX_REGEX_MATCH_SECONDS * 1.001


def test_idle_retry_keeps_existing_slack_semantics(monkeypatch):
    """无争用（倍率 1）时重试 timeout 仍是 剩余 x SLACK，和改动前一致。"""
    clocks = FakeClocks(monkeypatch)

    class Scripted:
        def __init__(self):
            self.timeouts = []

        def search(self, _content, *, timeout):
            self.timeouts.append(timeout)
            if len(self.timeouts) == 1:
                clocks.run(0.001, 1.0)
                raise TimeoutError
            return None

    pattern = Scripted()
    _install(monkeypatch, [pattern])
    CustomRuleSet([_rule("idle")]).match("payload")
    assert pattern.timeouts[1] == pytest.approx(0.009 * 10)


class BudgetEater:
    """一次 search 吃掉 burn 秒本线程 CPU，可选命中。"""

    def __init__(self, clocks, burn, result=None):
        self.clocks, self.burn, self.result, self.calls = clocks, burn, result, 0

    def search(self, _content, *, timeout):
        self.calls += 1
        self.clocks.run(self.burn, 1.0)
        return self.result

    def finditer(self, _content, *, timeout):
        found = self.search(_content, timeout=timeout)
        return iter([found] if found is not None else [])


def test_enforcing_rules_run_before_audit_rules_when_pack_budget_is_tight(monkeypatch):
    clocks = FakeClocks(monkeypatch)
    monkeypatch.setattr(custom_rules, "MAX_REGEX_RULESET_SECONDS", 0.05)
    monkeypatch.setattr(custom_rules, "MAX_REGEX_MATCH_SECONDS", 0.05)
    audit_heavy = BudgetEater(clocks, 0.06, result=Hit("AUDIT"))   # 一条就吃光整包预算
    block_rule = BudgetEater(clocks, 0.0001, result=Hit("BLOCK"))
    _install(monkeypatch, [audit_heavy, block_rule])
    ruleset = CustomRuleSet([_rule("tenant_audit"), _rule("builtin_block", action="block")])
    findings = ruleset.match("payload")
    assert block_rule.calls == 1
    assert ("builtin_block", "regex_budget_exhausted") not in ruleset.runtime_failure_counts
    assert ("builtin_block", "custom") in [(f.rule_id, f.type) for f in findings]


def test_findings_keep_rule_pack_order_after_priority_execution(monkeypatch):
    clocks = FakeClocks(monkeypatch)
    patterns = [
        BudgetEater(clocks, 0.0001, result=Hit("A1")),
        BudgetEater(clocks, 0.0001, result=Hit("B1")),
        BudgetEater(clocks, 0.0001, result=Hit("A2")),
        BudgetEater(clocks, 0.0001, result=Hit("M1")),
    ]
    _install(monkeypatch, patterns)
    rules = [_rule("a1"), _rule("b1", action="block"), _rule("a2"), _rule("m1", action="mask")]
    findings = CustomRuleSet(rules).match("payload")
    assert [f.rule_id for f in findings] == ["a1", "b1", "a2", "m1"]


@pytest.mark.skipif((os.cpu_count() or 1) < 4, reason="需要多核才能并行消耗进程 CPU")
def test_regex_library_timeout_counts_whole_process_cpu():
    """钉住第三方库语义：其它线程（不持 GIL）并行耗 CPU 时，regex timeout 会提前触发。

    若库改为按墙钟或本线程计时，这条会失败，提醒重新评估 regex_budget 的换算。
    """
    pattern = real_regex.compile(r"(\w+\s?)+\d")
    subject = "word " * 2000
    stop = threading.Event()
    blob = b"x" * (32 << 20)

    def burn():
        while not stop.is_set():
            hashlib.sha256(blob).digest()

    burners = [threading.Thread(target=burn, daemon=True) for _ in range(3)]
    for t in burners:
        t.start()
    try:
        time.sleep(0.05)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            pattern.search(subject, timeout=0.3)
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        for t in burners:
            t.join(timeout=5)
    assert elapsed < 0.2, f"timeout=0.3s 却在墙钟 {elapsed:.3f}s 才触发：库计时口径已变化"
