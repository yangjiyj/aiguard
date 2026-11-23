"""C3 cost model: window count == judge calls while the cascade is disabled.

These are deterministic measurements, not a substitute for the acceptance
replay: they price the window geometry, they do not measure recall.
"""
import re

from app.detectors import semantic as semantic_module
from app.detectors.semantic import plan_windows

NARROW = (1200, 200)
WIDE = (4000, 300)
MAX_WINDOWS = 32


def _windows(total, window, overlap, maximum=MAX_WINDOWS):
    return plan_windows(total, window, overlap, maximum)


def test_single_short_text_stays_one_window():
    assert _windows(900, *WIDE) == [(0, 900)]
    assert _windows(2000, *WIDE) == [(0, 2000)]


def test_wide_windows_cut_judge_calls_on_long_texts():
    # 8000 and 32000 characters are the measured 2k/8k/32k-char traffic shapes.
    assert len(_windows(8000, *NARROW)) == 8
    assert len(_windows(8000, *WIDE)) == 3
    assert len(_windows(32000, *NARROW)) == 32
    assert len(_windows(32000, *WIDE)) == 9
    for total in (8000, 32000):
        narrow = len(_windows(total, *NARROW))
        wide = len(_windows(total, *WIDE))
        assert wide <= narrow * 0.4, (total, wide, narrow)


def test_wide_windows_remove_the_truncation_that_narrow_windows_cause():
    # 60000 characters: 1200-char windows hit SECURITY_SEMANTIC_MAX_WINDOWS=32
    # and stop at 32200 (46% of the text never inspected); 4000-char windows
    # still cover everything inside the same budget.
    narrow = _windows(60000, *NARROW)
    wide = _windows(60000, *WIDE)
    assert len(narrow) == MAX_WINDOWS and narrow[-1][1] < 60000
    assert len(wide) == 17 and wide[-1][1] == 60000


def test_coverage_reaches_the_end_until_the_window_budget_is_hit():
    for total in (1, 3999, 4000, 4001, 8000, 32000):
        plan = _windows(total, *WIDE)
        assert plan and plan[-1][1] == total, (total, plan[-1])


def test_windows_are_contiguous_and_advance_by_window_minus_overlap():
    plan = _windows(30000, *WIDE)
    assert plan[0] == (0, 4000)
    for (_, end), (next_start, _) in zip(plan, plan[1:]):
        assert next_start == end - 300


def test_max_windows_is_a_hard_bound():
    assert len(_windows(10 ** 6, *WIDE)) == MAX_WINDOWS
    assert len(_windows(10 ** 6, *WIDE, maximum=3)) == 3


def test_overlap_is_clamped_below_the_window_size_so_the_plan_cannot_stall():
    assert _windows(10, 4, 99) == [
        (0, 4), (1, 5), (2, 6), (3, 7), (4, 8), (5, 9), (6, 10)]


def test_stop_callback_returns_a_partial_plan_when_the_request_budget_runs_out():
    calls = {"n": 0}

    def stop() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    plan = plan_windows(30000, *WIDE, MAX_WINDOWS, stop=stop)
    assert len(plan) == 2
    assert plan[-1][1] < 30000
    assert plan_windows(30000, *WIDE, MAX_WINDOWS, stop=lambda: True) == []


def test_detector_still_uses_the_pure_planner():
    source = open(semantic_module.__file__, encoding="utf-8").read()
    assert re.search(r"plan\s*=\s*plan_windows\(", source), (
        "the non-contextual window plan must stay on plan_windows() so this "
        "cost model keeps matching production"
    )
