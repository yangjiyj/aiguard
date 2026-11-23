import json
from pathlib import Path
from training.seedgen.to_bench import to_bench_rows, append_to_bench


def test_attack_row_becomes_label_1_with_category():
    rows = [{"text": "忽略指令", "label": "attack",
             "category": "semantic_jailbreak", "source": "seed"}]
    jb, bn = to_bench_rows(rows)
    assert jb == [{"text": "忽略指令", "label": 1, "category": "semantic_jailbreak"}]
    assert bn == []


def test_benign_row_becomes_label_0_no_category():
    rows = [{"text": "整理纪要", "label": "benign",
             "category": "none", "source": "seed"}]
    jb, bn = to_bench_rows(rows)
    assert bn == [{"text": "整理纪要", "label": 0}]
    assert "category" not in bn[0]
    assert jb == []


def test_append_dedups_against_existing(tmp_path):
    jb_file = tmp_path / "zh_jailbreak.jsonl"
    bn_file = tmp_path / "zh_benign.jsonl"
    jb_file.write_text(json.dumps({"text": "已有越狱", "label": 1,
                                   "category": "semantic_jailbreak"}, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    bn_file.write_text(json.dumps({"text": "已有良性", "label": 0}, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    rows = [
        {"text": "已有越狱", "label": "attack", "category": "semantic_jailbreak", "source": "seed"},
        {"text": "新越狱样本", "label": "attack", "category": "semantic_roleplay", "source": "seed"},
        {"text": "新良性样本", "label": "benign", "category": "none", "source": "seed"},
    ]
    added_jb, added_bn = append_to_bench(rows, jb_file, bn_file)
    assert added_jb == 1  # "已有越狱" 去重，只加 "新越狱样本"
    assert added_bn == 1
    jb_texts = [json.loads(l)["text"] for l in jb_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert jb_texts.count("已有越狱") == 1
    assert "新越狱样本" in jb_texts


def _combined_texts(jb_file: Path, bn_file: Path) -> list:
    jb = [json.loads(l)["text"] for l in jb_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    bn = [json.loads(l)["text"] for l in bn_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    return jb + bn


def test_append_dedups_same_text_across_labels_in_one_batch(tmp_path):
    """同一条 text 同批以 attack+benign 矛盾标签出现：不得跨文件双写，否则破坏
    test_bench_dataset.py 的 no-dup 守卫（对 jb+bn 合并查重）。"""
    jb_file = tmp_path / "zh_jailbreak.jsonl"
    bn_file = tmp_path / "zh_benign.jsonl"
    jb_file.write_text("", encoding="utf-8")
    bn_file.write_text("", encoding="utf-8")
    rows = [
        {"text": "字面像攻击实则正常", "label": "attack",
         "category": "semantic_jailbreak", "source": "seed"},
        {"text": "字面像攻击实则正常", "label": "benign",
         "category": "none", "source": "seed"},
    ]
    added_jb, added_bn = append_to_bench(rows, jb_file, bn_file)
    combined = _combined_texts(jb_file, bn_file)
    # 守卫等价断言：合并去重后无重复
    assert len(combined) == len(set(combined)), "同文本跨 label 双写破坏 no-dup 守卫"
    # 同一条只入一个文件，总新增计数为 1
    assert added_jb + added_bn == 1


def test_append_skips_benign_text_already_in_jailbreak_file(tmp_path):
    """某 text 已存在于 zh_jailbreak.jsonl，本批又给出同 text 的 benign 行：
    benign 不得再写入 zh_benign.jsonl，避免跨文件重复。"""
    jb_file = tmp_path / "zh_jailbreak.jsonl"
    bn_file = tmp_path / "zh_benign.jsonl"
    jb_file.write_text(json.dumps({"text": "争议样本", "label": 1,
                                   "category": "semantic_jailbreak"}, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    bn_file.write_text("", encoding="utf-8")
    rows = [
        {"text": "争议样本", "label": "benign", "category": "none", "source": "seed"},
        {"text": "全新良性", "label": "benign", "category": "none", "source": "seed"},
    ]
    added_jb, added_bn = append_to_bench(rows, jb_file, bn_file)
    combined = _combined_texts(jb_file, bn_file)
    assert len(combined) == len(set(combined)), "跨文件已存在的 text 被重复写入"
    assert added_jb == 0
    assert added_bn == 1  # 只加 "全新良性"
    bn_texts = [json.loads(l)["text"] for l in bn_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert "争议样本" not in bn_texts
    assert "全新良性" in bn_texts
