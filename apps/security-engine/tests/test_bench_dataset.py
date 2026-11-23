import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "bench" / "data"
_CATEGORIES = {
    "semantic_jailbreak", "semantic_roleplay",
    "semantic_instruction_override", "semantic_exfil_induce",
}


def _load(name):
    lines = (DATA_DIR / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(ln) for ln in lines if ln.strip()]


def test_jailbreak_file_exists_and_nonempty():
    rows = _load("zh_jailbreak.jsonl")
    assert len(rows) >= 40, "越狱集至少 40 条，小而真"


def test_benign_file_exists_and_nonempty():
    rows = _load("zh_benign.jsonl")
    assert len(rows) >= 40, "良性集至少 40 条，覆盖易误报场景"


def test_jailbreak_schema_and_labels():
    for r in _load("zh_jailbreak.jsonl"):
        assert set(r) >= {"text", "label", "category"}
        assert r["label"] == 1
        assert isinstance(r["text"], str) and r["text"].strip()
        assert r["category"] in _CATEGORIES, f"category 必须落在 semantic.py 的 _CATEGORY_CN key: {r['category']}"


def test_benign_schema_and_labels():
    for r in _load("zh_benign.jsonl"):
        assert set(r) >= {"text", "label"}
        assert r["label"] == 0
        assert isinstance(r["text"], str) and r["text"].strip()


def test_benign_covers_hard_negatives():
    """良性集必须含"看着像攻击其实正常"的硬负样本（角色扮演/安全研究/运维），否则误升级率虚低。"""
    texts = " ".join(r["text"] for r in _load("zh_benign.jsonl"))
    assert "扮演" in texts            # 良性角色扮演（写作/翻译）
    assert "渗透测试" in texts or "安全" in texts  # 安全从业者合法提问
    assert "系统提示" in texts or "配置" in texts  # 运维问配置（非越狱诱导）


def test_all_categories_represented():
    cats = {r["category"] for r in _load("zh_jailbreak.jsonl")}
    assert cats == _CATEGORIES, f"5 类越狱意图都要有样本，缺: {_CATEGORIES - cats}"


def test_no_duplicate_texts():
    all_texts = [r["text"] for r in _load("zh_jailbreak.jsonl")] + [r["text"] for r in _load("zh_benign.jsonl")]
    assert len(all_texts) == len(set(all_texts)), "去重，防同一条占召回/精度便宜"
