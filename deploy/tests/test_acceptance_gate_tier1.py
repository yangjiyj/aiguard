import json
import os
import re
import subprocess

HERE = os.path.dirname(__file__)
GATE = os.path.abspath(os.path.join(HERE, "..", "lib", "acceptance-gate.sh"))


def _body():
    with open(GATE, "r", encoding="utf-8") as f:
        return f.read()


def test_tier1_assertions_present():
    body = _body()
    # 越狱高分 + 良性低分两条核心断言仍在（自训模型须满足）
    assert "越狱样本高分" in body
    assert "良性样本低分" in body
    assert "0.8" in body  # HIGH 阈值断言


def test_tier1_comment_is_selftrained_not_promptguard():
    body = _body()
    # 验收闸文案对齐自训口径（不得再写 Prompt-Guard）
    assert "Prompt-Guard" not in body
    assert "自训" in body


# ---------- RFIX-2c: 越狱>=0.8 阈值 + stub 用真实 (label,proba(n,2)) 签名，不假绿 ----------

def _shell_score_extract_and_threshold(classify_json: str, op: str, bound: str) -> bool:
    """逐字复刻 acceptance-gate.sh 的 score 抽取 + awk 阈值判定（真拿 /bin/sh + awk 跑）。

    抽取：grep -oE '"score"...[0-9.]+' | grep -oE '[0-9.]+$' | head -1
    判定：越狱 awk '($TJS>=0.8)'；良性 awk '($TBS<0.8)'。
    返回该断言在 gate 里是否会判为通过（exit 0）。"""
    script = (
        'JSON="$1"; '
        r"""S="$(printf '%s' "$JSON" | grep -oE '"score"[[:space:]]*:[[:space:]]*[0-9.]+' | grep -oE '[0-9.]+$' | head -1)"; """
        f'[ -n "$S" ] && awk "BEGIN{{exit !($S{op}{bound})}}"'
    )
    rc = subprocess.run(["/bin/sh", "-c", script, "_", classify_json]).returncode
    return rc == 0


def _real_classify_json(proba_row):
    """用**真 ModelScorer** + 真实融合签名 (label int64 (n,), probabilities float (n,2)) 的假 session，
    产出 /classify 会返回的 JSON（{score,label}）——不写死分数，score 来自 proba[:,1] 的真实抽取。"""
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "apps", "tier1-classifier")))
    import numpy as np
    from app.model import ModelScorer

    class _Inp:
        def __init__(self, n): self.name = n

    class _Sess:
        def __init__(self, proba): self._p = np.asarray(proba, dtype=np.float32)
        def get_inputs(self): return [_Inp("input_ids"), _Inp("attention_mask")]
        def run(self, _o, inputs):
            assert "input_ids" in inputs and "attention_mask" in inputs
            return [np.argmax(self._p, axis=1).astype(np.int64), self._p]

    def _tok(text, truncation, max_length, return_tensors, **kwargs):
        assert kwargs["return_overflowing_tokens"] is True
        assert kwargs["stride"] > 0
        return {"input_ids": np.array([[1, 2, 3]], dtype=np.int64),
                "attention_mask": np.array([[1, 1, 1]], dtype=np.int64)}

    scorer = ModelScorer(_Sess([proba_row]), _tok, {0: "benign", 1: "attack"})
    score, label = scorer.score("样本")
    score = max(0.0, min(1.0, float(score)))  # 与 main.py /classify 同钳位
    return json.dumps({"score": score, "label": str(label), "coverage_complete": True})


def test_gate_high_threshold_is_0_8_on_real_attack_proba():
    """越狱：真实融合 proba[:,1]≈1.0（RFIX-1 修输出契约后可达）→ /classify score≈1.0，
    经 gate 的 score 抽取 + awk 断言 (>=0.8) 应通过。证明 0.8 阈值对真攻击概率可达成。"""
    j = _real_classify_json([0.0, 1.0])  # attack 概率(列1)=1.0
    assert re.search(r'"score":\s*1\.0', j), f"真攻击 score 应≈1.0，实得 {j}"
    assert _shell_score_extract_and_threshold(j, ">=", "0.8") is True


def test_gate_high_threshold_rejects_low_attack_score():
    """反例（防假绿）：若 score 抽取/契约错导致攻击样本只得 0.5，gate 的 >=0.8 断言必须判失败，
    而不是无论如何都绿。确保断言真在起作用。"""
    j = _real_classify_json([0.5, 0.5])  # attack 概率(列1)=0.5 < 0.8
    assert _shell_score_extract_and_threshold(j, ">=", "0.8") is False


def test_gate_benign_low_threshold_on_real_benign_proba():
    """良性：真实融合 proba[:,1]≈0.02 → /classify score≈0.02，经 gate 的 <0.8 断言应通过。"""
    j = _real_classify_json([0.98, 0.02])  # attack 概率(列1)=0.02
    assert _shell_score_extract_and_threshold(j, "<", "0.8") is True



def test_model_smoke_is_not_claimed_as_final_detection():
    body = _body()
    assert "直出 finding" not in body
    assert "模型分数冒烟，非最终检测结论" in body


def test_short_http_probe_rejects_missing_or_false_coverage(monkeypatch, capsys):
    import urllib.request
    body = _body()
    start = body.index("import os, json, urllib.request", body.index("t1_classify()"))
    end = body.index("' 2>/dev/null", start)
    code = body[start:end]
    monkeypatch.setenv("T1BODY", '{"text":"synthetic"}')
    monkeypatch.setenv("T1TOK", "synthetic-test-only")
    class Reply:
        def __init__(self, complete):
            self.complete = complete
        def read(self):
            return json.dumps({"score": .99, "label": "attack", **self.complete}).encode()
    for coverage in ({}, {"coverage_complete": False}, {"coverage_complete": "true"}):
        monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Reply(coverage))
        exec(compile(code, "acceptance-t1-http", "exec"), {})
        assert "ERR:" in capsys.readouterr().out
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Reply({"coverage_complete": True}))
    exec(compile(code, "acceptance-t1-http", "exec"), {})
    assert json.loads(capsys.readouterr().out)["coverage_complete"] is True


def test_long_window_runtime_probe_is_wired_into_gate():
    body = _body()
    assert "tier1-window-smoke.py" in body
    assert 'docker exec -i -e T1TOK "$TN" python -' in body



def _window_probe_module():
    import importlib.util
    path = os.path.abspath(os.path.join(HERE, "..", "lib", "tier1-window-smoke.py"))
    spec = importlib.util.spec_from_file_location("tier1_window_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_long_probe_requires_multiple_token_windows_and_true_http_coverage(monkeypatch):
    import urllib.request
    import pytest
    module = _window_probe_module()
    seen = []
    class Tokenizer:
        def __call__(self, text, **kwargs):
            if not kwargs["truncation"]:
                return {"input_ids": [1] * 900}
            assert kwargs["max_length"] == 512 and kwargs["return_overflowing_tokens"] is True
            return {"input_ids": [[1] * 512, [2] * 512]}
    class Reply:
        status = 200
        def __init__(self, coverage): self.coverage = coverage
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            return json.dumps({"score": .01, "label": "benign", "coverage_complete": self.coverage}).encode()
    monkeypatch.setenv("T1TOK", "synthetic-only")
    def request(req, timeout):
        seen.append(json.loads(req.data)["text"])
        assert req.full_url == "http://127.0.0.1:8000/classify"
        return Reply(True)
    monkeypatch.setattr(urllib.request, "urlopen", request)
    result = module.run_probe(Tokenizer())
    assert result["tokens"] == 900 and result["token_windows"] == 2
    assert result["coverage_complete"] is True
    assert result["accuracy_claim"] is False
    assert 512 < len(seen[0]) <= 4096
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Reply(False))
    with pytest.raises(ValueError, match="coverage_complete"):
        module.run_probe(Tokenizer())


def test_long_probe_rejects_fixture_that_does_not_exceed_512_tokens():
    import pytest
    module = _window_probe_module()
    class ShortTokenizer:
        def __call__(self, text, **kwargs):
            return {"input_ids": [1] * 20 if not kwargs["truncation"] else [[1] * 20]}
    with pytest.raises(ValueError, match="more than one"):
        module.build_long_fixture(ShortTokenizer())
