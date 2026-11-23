"""关键词组合规则误报整改的前后对比（只读，输出 JSON）。

用法（在 apps/security-engine 下）：
    python3 bench/catalog_fp_compare.py --repo ../.. > /tmp/after.json
在改动前的检出上用同一命令得到 before.json，再对比两份 JSON。

统计三份样本里“计入告警”的命中，按 finding 类别计数：
- zh_benign：bench/data/zh_benign.jsonl（正常请求）
- zh_jailbreak：bench/data/zh_jailbreak.jsonl（越狱请求）
- repo_text：仓库自己的 CLAUDE.md、AGENTS.md、docs/**/*.md 段落和最近 500 条提交说明，
  当作编程流量样本（内容是开发文档，命中基本都是误报）
引擎开关与生产默认一致（同 tests/test_capability_docs.PRODUCTION_ENGINE_ENV）。
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_capability_docs import PRODUCTION_ENGINE_ENV  # noqa: E402


def _engine():
    os.environ.update(PRODUCTION_ENGINE_ENV)
    from app.detectors.engine import SecurityEngine
    return SecurityEngine()


def _jsonl(path):
    return [json.loads(line)["text"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _repo_text(repo: pathlib.Path):
    texts = []
    files = [repo / "CLAUDE.md", repo / "AGENTS.md", *sorted((repo / "docs").rglob("*.md"))]
    for path in files:
        if not path.is_file():
            continue
        for block in path.read_text(encoding="utf-8", errors="ignore").split("\n\n"):
            block = block.strip()
            if 20 <= len(block) <= 4000:
                texts.append(block)
    log = subprocess.run(["git", "-C", str(repo), "log", "-500", "--format=%B%x1e"],
                         capture_output=True, text=True, check=True).stdout
    texts.extend(part.strip() for part in log.split("\x1e") if part.strip())
    return texts


def _count(engine, texts):
    counted = collections.Counter()
    hit_texts = any_alert = 0
    for index, text in enumerate(texts):
        result = engine.check_input(f"compare-{index}", text, content_source="user")
        alerts = [f for f in result.findings if f.counts_as_security_finding]
        cats = {f.category for f in alerts if f.type in {"catalog_policy", "content_safety"}}
        counted.update(cats)
        hit_texts += bool(cats)
        any_alert += bool(alerts)
    return {"texts": len(texts), "texts_with_keyword_alert": hit_texts, "texts_with_any_alert": any_alert,
            "by_category": dict(sorted(counted.items()))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT.parents[1]))
    args = parser.parse_args()
    engine = _engine()
    data = ROOT / "bench" / "data"
    report = {
        "zh_benign": _count(engine, _jsonl(data / "zh_benign.jsonl")),
        "zh_jailbreak": _count(engine, _jsonl(data / "zh_jailbreak.jsonl")),
        "repo_text": _count(engine, _repo_text(pathlib.Path(args.repo))),
    }
    json.dump(report, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main()
