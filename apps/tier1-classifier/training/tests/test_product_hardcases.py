import json

from training.product_hardcases import (
    ATTACK_SPECS,
    PRODUCT_DOMAINS,
    SPLITS,
    generate_splits,
    write_splits,
)


def test_generation_is_balanced_and_covers_product_surface():
    splits = generate_splits()
    rows = [row for name in SPLITS for row in splits[name]]
    assert len(rows) >= 3000
    assert {row["label"] for row in rows} == {"attack", "benign"}
    assert sum(row["label"] == "attack" for row in rows) == sum(
        row["label"] == "benign" for row in rows
    )
    assert {row["business_domain"] for row in rows} == {item[0] for item in PRODUCT_DOMAINS}
    assert {row["source"] for row in rows} >= {
        "user", "tool_result", "rag", "attachment", "email", "web",
    }
    assert {row["stage"] for row in rows} >= {"input", "agent", "tool_result"}
    assert {category for row in rows for category in row["categories"]} == {
        item[1] for item in ATTACK_SPECS
    }
    assert all(len(row["content_sha256"]) == 64 and len(row["record_sha256"]) == 64
               for row in rows)


def test_each_contrast_set_has_one_attack_and_one_benign():
    for rows in generate_splits().values():
        grouped = {}
        for row in rows:
            grouped.setdefault(row["contrast_set_id"], []).append(row)
        assert grouped
        assert all(sorted(item["label"] for item in pair) == ["attack", "benign"]
                   for pair in grouped.values())


def test_split_families_and_text_never_cross():
    splits = generate_splits()
    for left_index, left in enumerate(SPLITS):
        left_groups = {row["split_group"] for row in splits[left]}
        left_texts = {row["text"] for row in splits[left]}
        for right in SPLITS[left_index + 1:]:
            assert left_groups.isdisjoint(row["split_group"] for row in splits[right])
            assert left_texts.isdisjoint(row["text"] for row in splits[right])


def test_holdout_is_explicitly_training_prohibited():
    splits = generate_splits()
    assert all(row["dataset_use"] == "evaluation_only_no_training"
               and row["training_prohibited"] is True
               for row in splits["holdout"])
    assert all("training_prohibited" not in row
               for name in ("train", "calibration", "validation")
               for row in splits[name])


def test_generation_is_deterministic_and_writes_manifest(tmp_path):
    first = generate_splits()
    second = generate_splits()
    assert first == second
    report = write_splits(tmp_path / "data", tmp_path / "report.json")
    assert report["passed"] is True
    assert set(report["rows"]) == set(SPLITS)
    assert len(report["sha256"]) == len(SPLITS)
    for name in SPLITS:
        rows = [json.loads(line) for line in
                (tmp_path / "data" / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()]
        assert rows == first[name]


def test_forbidden_exact_text_is_rejected(tmp_path):
    sample = generate_splits()["train"][0]["text"]
    forbidden = tmp_path / "forbidden.jsonl"
    forbidden.write_text(json.dumps({"text": sample}, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        write_splits(tmp_path / "data", tmp_path / "report.json", [forbidden])
    except ValueError as exc:
        assert "forbidden" in str(exc).lower()
    else:
        raise AssertionError("forbidden reference overlap was accepted")
