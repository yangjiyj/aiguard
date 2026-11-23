import pytest
from qwen_guard_reference import parse_guard_output

def test_native_labels_remain_distinct():
    assert parse_guard_output("Safety: Controversial\nCategories: Unethical Acts")["safety"]=="Controversial"
    assert parse_guard_output("Safety: Safe\nCategories: None")["categories"]==["None"]

def test_conflicting_or_unrecognized_output_is_not_safe():
    for text in ["Safety: Safe\nCategories: Jailbreak", "Safety: Unsafe\nCategories: None",
                 "Safety: Safe\nCategories: None\nSafety: Unsafe", "Safety: Safe"]:
        with pytest.raises(ValueError):parse_guard_output(text)
