"""Execute inside the target Tier1 image; model compatibility smoke, never accuracy evidence."""
import importlib.metadata
import json
import math
import os
import sys
import urllib.request


PARAGRAPH = "这是一段用于离线交付验收的中文长文本，验证中间和末尾内容都经过分类处理。"


def build_long_fixture(tokenizer):
    text = PARAGRAPH * 40
    if len(text) > 4096:
        raise ValueError("fixture exceeds HTTP character budget")
    token_count = len(tokenizer(text, truncation=False)["input_ids"])
    encoded = tokenizer(text, truncation=True, max_length=512, return_overflowing_tokens=True,
                        stride=64, padding=True, return_tensors="np")
    windows = len(encoded["input_ids"])
    if token_count <= 512 or windows <= 1:
        raise ValueError("fixture must exercise more than one real token window")
    return text, token_count, windows


def run_probe(tokenizer):
    text, tokens, windows = build_long_fixture(tokenizer)
    request = urllib.request.Request("http://127.0.0.1:8000/classify",
        data=json.dumps({"text": text}, ensure_ascii=False).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-JJDGuard-Internal-Token": os.environ["T1TOK"]})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("classify must succeed")
        payload = json.loads(response.read(65537))
    if payload.get("coverage_complete") is not True:
        raise ValueError("coverage_complete must be true")
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("score must be a finite probability")
    if not isinstance(payload.get("label"), str):
        raise ValueError("classify label contract invalid")
    # Do not print sample text, tokens/credentials, or infer attack recall from this probe.
    return {"chars": len(text), "tokens": tokens, "token_windows": windows,
            "http_rows": 1, "coverage_complete": True, "accuracy_claim": False}


def main():
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(os.environ.get("TIER1_MODEL_DIR", "/models/prompt-guard-2"),
                                                  local_files_only=True)
        result = run_probe(tokenizer)
        result["python"] = sys.version.split()[0]
        result["dependencies"] = {name: importlib.metadata.version(name)
                                  for name in ("onnxruntime", "transformers", "numpy", "tokenizers")}
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"coverage_complete": False, "error": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
