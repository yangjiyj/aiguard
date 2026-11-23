"""目录规则源码守护：只能用构造函数写英文，不能用 \\b，每个英文片段两侧边界实测。"""
import ast
import inspect
import re
import re._parser as sre_parse

from app.detectors import policy_catalog as catalog
from app.detectors.catalog_terms import exact, stem, w


def _sample(pattern):
    """A shortest string the fragment matches (catalog grammar only)."""
    out = []

    def walk(items):
        for op, av in items:
            name = str(op)
            if name == "LITERAL":
                out.append(chr(av))
            elif name == "IN":
                for item_op, item_av in av:
                    if str(item_op) == "LITERAL":
                        out.append(chr(item_av))
                        break
                    if str(item_op) == "RANGE":
                        out.append(chr(item_av[0]))
                        break
                    if str(item_op) == "CATEGORY":
                        out.append("a" if "WORD" in str(item_av) else "1" if "DIGIT" in str(item_av) else " ")
                        break
            elif name in ("MAX_REPEAT", "MIN_REPEAT"):
                low, _high, sub = av
                for _ in range(low):
                    walk(sub)
            elif name == "SUBPATTERN":
                walk(av[-1])
            elif name == "BRANCH":
                walk(av[1][0])
            elif name == "ANY":
                out.append("a")
            elif name == "CATEGORY":
                out.append("a" if "WORD" in str(av) else "1" if "DIGIT" in str(av) else " ")

    walk(sre_parse.parse(pattern))
    return "".join(out)


def test_rules_are_built_with_constructors():
    tree = ast.parse(inspect.getsource(catalog))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_rx"]
    assert calls
    assert not [n.lineno for n in calls if isinstance(n.args[0], ast.Constant)]


def test_catalog_sources_have_no_word_boundary_escape():
    assert catalog.CATALOG_SOURCES
    assert not [s for s in catalog.CATALOG_SOURCES if "\\b" in s]


def test_every_declared_english_fragment_keeps_its_boundaries():
    checked = 0
    for fragment in {f for f in catalog.CATALOG_FRAGMENTS}:
        build = stem if fragment.stem else (w if fragment.inflected else exact)
        pattern = re.compile(build(fragment.source).source, re.IGNORECASE | re.DOTALL)
        sample = _sample(fragment.source)
        assert pattern.search("中" + sample + "中"), fragment
        if fragment.left:
            assert not pattern.search("x" + sample), fragment
        if fragment.right and not fragment.stem:
            assert not pattern.search(sample + "x"), fragment
        checked += 1
    assert checked > 500
