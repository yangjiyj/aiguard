from app.latency_stats import LatencyStats


def test_empty_snapshot_is_zero():
    s = LatencyStats(capacity=8)
    snap = s.snapshot()
    # scored_count 是自文档字段名（只统计成功打分次数）；classify_count 为向后兼容别名，两者同值。
    assert snap == {
        "scored_count": 0,
        "classify_count": 0,
        "latency_p50_ms": 0.0,
        "latency_p95_ms": 0.0,
    }


def test_scored_count_aliases_classify_count():
    """scored_count 与 classify_count 恒同值：仅计成功打分（record() 调用），
    503/短路路径不 record，故二者都排除失败/未打分请求。"""
    s = LatencyStats(capacity=8)
    for v in (5.0, 6.0, 7.0):
        s.record(v)
    snap = s.snapshot()
    assert snap["scored_count"] == 3
    assert snap["scored_count"] == snap["classify_count"]


def test_percentiles_over_samples():
    s = LatencyStats(capacity=100)
    for v in range(1, 101):          # 1..100 ms
        s.record(float(v))
    snap = s.snapshot()
    assert snap["classify_count"] == 100
    # 最近邻百分位:p50≈50,p95≈95(允许±1容忍实现取整)
    assert 49.0 <= snap["latency_p50_ms"] <= 51.0
    assert 94.0 <= snap["latency_p95_ms"] <= 96.0


def test_ring_buffer_evicts_oldest():
    s = LatencyStats(capacity=3)
    for v in (10.0, 20.0, 30.0, 40.0, 50.0):   # 仅保留最近 3 个:30/40/50
        s.record(v)
    snap = s.snapshot()
    assert snap["classify_count"] == 5          # 累计计数不因淘汰归零
    assert snap["latency_p50_ms"] == 40.0       # 窗口内中位数
    assert snap["latency_p95_ms"] == 50.0


def test_record_never_raises_on_bad_value():
    s = LatencyStats(capacity=4)
    s.record(float("nan"))       # 不得抛异常(热路径记录点绝不冒泡)
    s.record(-5.0)               # 负值忽略,不入缓冲
    assert s.snapshot()["classify_count"] == 0
