"""关键词组合规则误报整改的回归用例（设计：docs/superpowers/specs/2026-11-14-catalog-false-positive-design.md）。

每条用例写明期望：none（不出该类别的 finding）、observation（只留证、不计入告警）、
counted（计入告警）。引擎开关与生产默认一致（见 test_capability_docs.PRODUCTION_ENGINE_ENV）。
"""
import json
from pathlib import Path

import pytest

from test_capability_docs import _engine

CASES = json.loads((Path(__file__).parent / "data" / "catalog_fp_cases.json").read_text(encoding="utf-8"))


def test_case_table_is_well_formed():
    assert len(CASES) >= 150
    for case in CASES:
        assert set(case) <= {"category", "text", "expect", "stage", "source", "from"}
        assert case["expect"] in {"none", "observation", "counted"}
        assert case.get("stage", "input") in {"input", "output"}
        assert case["from"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['category']}|{c['expect']}|{c['text'][:20]}")
def test_catalog_fp_case(case, monkeypatch):
    engine = _engine(monkeypatch)
    if case.get("stage") == "output":
        result = engine.check_output("catalog-fp-case", case["text"])
    else:
        result = engine.check_input("catalog-fp-case", case["text"], content_source=case.get("source", "user"))
    found = [f for f in result.findings if f.category == case["category"]]
    counted = [f for f in found if f.counts_as_security_finding]
    if case["expect"] == "none":
        assert not found, f"期望不命中，实际：{[(f.category, f.counts_as_security_finding) for f in found]}"
    elif case["expect"] == "observation":
        assert found and not counted, f"期望只留证，实际 finding {len(found)} 条、计入告警 {len(counted)} 条"
    else:
        assert counted, f"期望计入告警，实际 finding {len(found)} 条、计入告警 0 条"
