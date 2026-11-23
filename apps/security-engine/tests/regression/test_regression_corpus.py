"""固定回归样本集：必须报（attack）/ 必须不报（benign）。

语料：同目录 corpus.jsonl，每行一个样本，字段
  id              样本编号
  text            送检文本（全部自编：密钥为随机现造，身份证校验位自算，银行卡为 Luhn 合法的测试号）
  content_source  user / tool_result / model_output（model_output 走输出侧检测）
  agent_type      空串或 claude-code 等
  label           attack 或 benign
  expect          attack 期望命中的类别前缀列表，命中其中任一个即通过；
                  needs_judge 的 attack 留空，表示只要有任一计入的 high/critical 命中
  needs_judge     true 表示要语义判官才可能判对
  xfail           （可选）已知缺口/误报的原因；挂 xfail(strict=True)，修好后会变成 XPASS 失败，提醒删掉这个字段

判定
  attack  有 counts_as_security_finding 不为 False 的命中，且类别以 expect 中某个前缀开头
  benign  没有任何计入的 high/critical 命中

跑法（在 apps/security-engine 下）
  默认（不需要判官，skip_semantic=True）：
      python -m pytest tests/regression -q
  连同需要判官的样本一起跑（要求引擎已配置可用的语义判官/模型服务，否则这些样本会按“没检出”记失败）：
      JJD_REGRESSION_JUDGE=1 python -m pytest tests/regression -q
  结尾会打印检出率与误报率（含 xfail 样本的实际结果，不含被跳过的判官样本）。
"""
import json
import os
from pathlib import Path

import pytest

from app.detectors.engine import SecurityEngine

CORPUS = Path(__file__).with_name("corpus.jsonl")
RUN_JUDGE = os.environ.get("JJD_REGRESSION_JUDGE") == "1"
HIGH = {"high", "critical"}


# 语料里的随机现造令牌在中间插了 {{JOIN}}，加载时去掉再送检。
# 这样仓库里不出现完整的令牌字面量，免得被代码托管平台的密钥扫描当成真密钥拦下。
JOIN_MARK = "{{JOIN}}"


def _load():
    samples = [json.loads(line) for line in CORPUS.read_text(encoding="utf8").splitlines() if line.strip()]
    for sample in samples:
        sample["text"] = sample["text"].replace(JOIN_MARK, "")
    return samples


SAMPLES = _load()
_RESULTS = {"attack": [0, 0], "benign": [0, 0]}  # label -> [样本数, 命中数/误报数]


@pytest.fixture(scope="module")
def engine():
    # 固定成现场的取值：来源感知在现场是开着的；不固定时结果会随别的用例留下的环境变量变化。
    patch = pytest.MonkeyPatch()
    patch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    patch.setenv("SECURITY_PII_CHECKSUM_ENABLED", "true")
    patch.setenv("SECURITY_PII_CHECKSUM_DROP_INVALID", "true")
    try:
        from app import feature_flags
        feature_flags.apply_overrides({})
        yield SecurityEngine()
    finally:
        patch.undo()


@pytest.fixture(scope="module", autouse=True)
def _print_rates(request):
    yield
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    atk, ben = _RESULTS["attack"], _RESULTS["benign"]
    mode = "含判官样本" if RUN_JUDGE else "不含判官样本"
    reporter.write_line("")
    reporter.write_line(
        f"[回归集·{mode}] 检出率 {atk[1]}/{atk[0]}"
        + (f" = {atk[1] / atk[0]:.1%}" if atk[0] else "")
        + f"；误报率 {ben[1]}/{ben[0]}"
        + (f" = {ben[1] / ben[0]:.1%}" if ben[0] else "")
    )


def _run(engine, sample):
    ctx = {"agent_type": sample["agent_type"]} if sample["agent_type"] else {}
    skip_semantic = not sample["needs_judge"]
    if sample["content_source"] == "model_output":
        result = engine.check_output("regression", sample["text"], context=ctx, skip_semantic=skip_semantic)
    else:
        result = engine.check_input(
            "regression", sample["text"], context=ctx, skip_semantic=skip_semantic,
            agent_type=sample["agent_type"] or None, content_source=sample["content_source"],
        )
    return [f for f in result.findings if getattr(f, "counts_as_security_finding", True) is not False]


def _param(sample):
    marks = []
    if sample["needs_judge"] and not RUN_JUDGE:
        marks.append(pytest.mark.skip(reason="需要判官，设 JJD_REGRESSION_JUDGE=1 才跑"))
    if sample.get("xfail"):
        marks.append(pytest.mark.xfail(strict=True, reason=sample["xfail"]))
    return pytest.param(sample, id=sample["id"], marks=marks)


def _cats(findings):
    return [(getattr(f, "category", None) or f.type) for f in findings]


@pytest.mark.parametrize("sample", [_param(s) for s in SAMPLES if s["label"] == "attack"])
def test_attack_detected(engine, sample):
    findings = _run(engine, sample)
    if sample["expect"]:
        detected = any(c.startswith(tuple(sample["expect"])) for c in _cats(findings))
    else:
        detected = any(f.severity in HIGH for f in findings)
    _RESULTS["attack"][0] += 1
    _RESULTS["attack"][1] += int(detected)
    assert detected, f"漏报 {sample['id']}：期望 {sample['expect'] or '任一 high/critical'}，实际 {sorted(set(_cats(findings)))}"


@pytest.mark.parametrize("sample", [_param(s) for s in SAMPLES if s["label"] == "benign"])
def test_benign_not_flagged(engine, sample):
    findings = [f for f in _run(engine, sample) if f.severity in HIGH]
    _RESULTS["benign"][0] += 1
    _RESULTS["benign"][1] += int(bool(findings))
    assert not findings, f"误报 {sample['id']}：{sorted({(c, f.severity) for c, f in zip(_cats(findings), findings)})}"


def test_corpus_shape():
    """语料规模与字段约束，防止有人删样本凑绿。"""
    ids = [s["id"] for s in SAMPLES]
    assert len(ids) == len(set(ids)), "样本 id 重复"
    count = lambda label, judge: sum(1 for s in SAMPLES if s["label"] == label and s["needs_judge"] == judge)
    assert count("attack", False) >= 80
    assert count("benign", False) >= 80
    assert count("attack", True) >= 15
    assert count("benign", True) >= 15
    for s in SAMPLES:
        assert s["label"] in ("attack", "benign")
        assert s["content_source"] in ("user", "tool_result", "model_output")
        if s["label"] == "attack" and not s["needs_judge"]:
            assert s["expect"], s["id"]
