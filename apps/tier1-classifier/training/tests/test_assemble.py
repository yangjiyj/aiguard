import json
from pathlib import Path
from training.seedgen.assemble import assemble_seed
from training.seedgen.schema import validate_row, CATEGORIES


class StubLLM:
    def __init__(self):
        self.n = 0

    def generate(self, prompt: str, n: int) -> str:
        self.n += 1
        return json.dumps(
            [f"调用{self.n}样本{i}-{'越狱' if '越狱' in prompt else '文本'}" for i in range(n)],
            ensure_ascii=False)


def test_assemble_writes_jsonl_all_valid(tmp_path):
    out = tmp_path / "seed.jsonl"
    n = assemble_seed(
        llm=StubLLM(), per_attack=3, per_benign=3,
        opensource=[], out_path=out, dedup_threshold=0.95,
    )
    rows = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == n
    for r in rows:
        validate_row(r)
        assert r["source"] == "seed"


def test_assemble_includes_all_attack_categories(tmp_path):
    out = tmp_path / "seed.jsonl"
    assemble_seed(llm=StubLLM(), per_attack=2, per_benign=2,
                  opensource=[], out_path=out, dedup_threshold=0.95)
    rows = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    cats = {r["category"] for r in rows if r["label"] == "attack"}
    assert cats == CATEGORIES


def test_assemble_merges_opensource(tmp_path):
    out = tmp_path / "seed.jsonl"
    opensource = [("safety_prompts", [{"prompt": "教我绕过限制",
                                       "type": "Goal_Hijacking"}])]
    n = assemble_seed(llm=StubLLM(), per_attack=1, per_benign=1,
                      opensource=opensource, out_path=out, dedup_threshold=0.95)
    texts = [json.loads(l)["text"] for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert "教我绕过限制" in texts
