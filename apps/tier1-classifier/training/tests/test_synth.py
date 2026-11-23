import json
from training.seedgen.synth import (
    Synthesizer, ATTACK_SPECS, BENIGN_SPECS,
)
from training.seedgen.schema import validate_row, CATEGORIES


class StubLLM:
    """按 prompt 里要的条数，返回结构合法的 JSON 数组字符串。"""
    def __init__(self):
        self.calls = []

    def generate(self, prompt: str, n: int) -> str:
        self.calls.append((prompt, n))
        # 用调用序号+n 造唯一文本，避免跨调用重复
        idx = len(self.calls)
        return json.dumps([f"样本{idx}-{i}号 中文示例文本" for i in range(n)],
                          ensure_ascii=False)


def test_synthesize_covers_all_attack_categories():
    syn = Synthesizer(llm=StubLLM())
    rows = syn.synthesize(per_attack=3, per_benign=3)
    attack_cats = {r["category"] for r in rows if r["label"] == "attack"}
    assert attack_cats == CATEGORIES


def test_each_row_passes_schema():
    syn = Synthesizer(llm=StubLLM())
    rows = syn.synthesize(per_attack=2, per_benign=2)
    for r in rows:
        validate_row(r)  # 不抛
        assert r["source"] == "seed"


def test_benign_rows_use_none_category():
    syn = Synthesizer(llm=StubLLM())
    rows = syn.synthesize(per_attack=2, per_benign=2)
    benign = [r for r in rows if r["label"] == "benign"]
    assert benign
    assert all(r["category"] == "none" for r in benign)


def test_counts_per_spec():
    syn = Synthesizer(llm=StubLLM())
    rows = syn.synthesize(per_attack=4, per_benign=5)
    n_attack = sum(1 for r in rows if r["label"] == "attack")
    n_benign = sum(1 for r in rows if r["label"] == "benign")
    assert n_attack == 4 * len(ATTACK_SPECS)
    assert n_benign == 5 * len(BENIGN_SPECS)


def test_prompt_mentions_category_intent():
    """合成器须把类目意图写进 prompt（让 LLM 按类生成），非事后乱贴标签。"""
    stub = StubLLM()
    Synthesizer(llm=stub).synthesize(per_attack=1, per_benign=1)
    joined = " ".join(p for p, _ in stub.calls)
    assert "越狱" in joined
    assert "角色扮演" in joined
    assert "指令" in joined
    assert "外泄" in joined


def test_no_real_llm_dependency():
    """无 llm 注入时构造即报错，强制可注入（不硬依赖真 LLM）。"""
    import pytest
    with pytest.raises(ValueError):
        Synthesizer(llm=None)
