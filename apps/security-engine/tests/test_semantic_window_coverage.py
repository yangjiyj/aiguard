from app.detectors.llm_judge import SemanticOpinion
from app.detectors.semantic import SemanticDetector


def detector(**kwargs):
    return SemanticDetector(url="http://judge/", model="m", api_key="k", op_timeout=1, total_timeout=2, **kwargs)


class RecordingTier1:
    def __init__(self):
        self.seen = []

    def classify(self, content):
        self.seen.append(content)
        return (0.9 if "ATTACK" in content else 0.0, "attack")


def test_tail_middle_and_boundary_attacks_reach_same_judge_window(monkeypatch):
    import app.detectors.semantic as semantic
    judged = []
    def judge(text, **kwargs):
        judged.append(text)
        return SemanticOpinion("malicious", "semantic_instruction_override", .9, "override")
    monkeypatch.setattr(semantic, "judge_semantic", judge)
    for position in (0, 1197, 2100, 4500):
        client = RecordingTier1()
        content = "a" * position + "ATTACK" + "b" * (5000-position)
        result = detector(tier1_enabled=True, tier1_client=client).detect(content, "input")
        assert any(f["type"] == "semantic_attack" for f in result)
        assert client.seen == []
        assert any("ATTACK" in text for text in judged)
        assert all(len(text) <= 1600 for text in judged)
        assert not any(f["type"] == "semantic_telemetry" for f in result)
        judged.clear()


def test_single_window_boundary_keeps_short_fast_path(monkeypatch):
    import app.detectors.semantic as semantic
    judged = []
    def judge(content, **kwargs):
        judged.append(content)
        return SemanticOpinion("benign", "none", .9, "ok")
    monkeypatch.setattr(semantic, "judge_semantic", judge)
    tier1 = RecordingTier1()
    d = detector(tier1_enabled=True, tier1_client=tier1)
    assert d.detect("a" * 1200, "input") == []
    assert list(map(len, tier1.seen)) == [1200]
    assert judged == []
    tier1.seen.clear()
    assert d.detect("a" * 1201, "input") == []
    assert tier1.seen == []
    assert sorted(map(len, judged)) == [201, 1200]


def test_window_budget_is_explicit_not_a_safe_verdict(monkeypatch):
    import app.detectors.semantic as semantic
    monkeypatch.setattr(semantic, "judge_semantic", lambda *a, **k:
                        SemanticOpinion("benign", "none", .9, "ok"))
    monkeypatch.setenv("SECURITY_SEMANTIC_MAX_WINDOWS", "2")
    client = RecordingTier1()
    result = detector(tier1_enabled=True, tier1_client=client).detect("a" * 10000, "input")
    assert client.seen == []
    incomplete = [f for f in result if f["type"] == "semantic_telemetry"]
    assert incomplete and incomplete[0]["triage"]["semantic_status"] == "incomplete"
    assert incomplete[0]["triage"]["semantic_reason"] == "window_budget_exceeded"
    assert incomplete[0]["triage"]["scanned_chars"] < 10000
    assert incomplete[0]["counts_as_security_finding"] is False


def test_one_deadline_is_shared_by_all_windows(monkeypatch):
    instance = detector()
    deadlines = []
    def judge(content, deadline, **kwargs):
        deadlines.append(deadline)
        return SemanticOpinion("benign", "none", .9, "ok")
    monkeypatch.setattr(instance, "_judge_with_deadline", judge)
    assert instance.detect("a" * 5000, "input") == []
    assert len(deadlines) > 1
    assert len(set(deadlines)) == 1


def test_whole_text_low_score_cannot_hide_a_shorter_attack_window(monkeypatch):
    import app.detectors.semantic as semantic

    class DilutedTier1(RecordingTier1):
        def classify(self, content):
            self.seen.append(content)
            return (0.9 if len(content) <= 1200 and "ATTACK" in content else 0.1, "attack")

    judged = []
    def judge(content, **kwargs):
        judged.append(content)
        return SemanticOpinion("malicious", "semantic_instruction_override", .9, "override")

    monkeypatch.setattr(semantic, "judge_semantic", judge)
    for position in (0, 1197, 1880, 3550):
        tier1 = DilutedTier1()
        text = "x" * position + "ATTACK" + "x" * (3600 - position)
        findings = detector(tier1_enabled=True, tier1_client=tier1).detect(text, "input")
        assert any(f["type"] == "semantic_attack" for f in findings)
        assert tier1.seen == []
        assert any("ATTACK" in fragment for fragment in judged)
        judged.clear()
