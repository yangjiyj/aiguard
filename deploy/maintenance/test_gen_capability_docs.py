import importlib.util
import json
import pathlib

spec = importlib.util.spec_from_file_location("gen_capability_docs", pathlib.Path(__file__).with_name("gen_capability_docs.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def test_committed_copy_matches_the_engine_source():
    assert gen.TARGET.read_text(encoding="utf-8") == gen.render(), (
        "控制面的能力说明副本过期了，重新生成：python3 deploy/maintenance/gen_capability_docs.py"
    )


def test_render_is_sorted_and_stable(tmp_path):
    (tmp_path / "b.json").write_text(json.dumps([{"category": "zeta", "matches": "乙"}], ensure_ascii=False), encoding="utf-8")
    (tmp_path / "a.json").write_text(json.dumps([{"category": "alpha", "matches": "甲"}], ensure_ascii=False), encoding="utf-8")
    text = gen.render(tmp_path)
    assert [entry["category"] for entry in json.loads(text)] == ["alpha", "zeta"]
    assert text.endswith("\n") and "甲" in text and text == gen.render(tmp_path)


def test_render_rejects_duplicate_categories(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps([{"category": "same"}]), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps([{"category": "same"}]), encoding="utf-8")
    try:
        gen.render(tmp_path)
    except ValueError as error:
        assert "same" in str(error)
    else:
        raise AssertionError("重复的能力键应该报错")
