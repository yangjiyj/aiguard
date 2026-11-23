"""
违法关键词"暴力"裸词误伤治理（复用既有置信度门控，不改召回）。

设计：
- "暴力"单独出现且无加重语境（暴力美学/暴力情节/反对暴力）→ 低置信度（弱信号）
- "暴力" + 加重语境（实施/袭击/制造/血腥等），或本身强词（恐怖袭击/爆炸物制作/枪支买卖）→ 0.9
- 2.6.7：明确的描述性弱线索仅作 observation，不计安全事件；门控开关不改变该边界
- 强信号仍由真实绑定策略决定处置
"""
import pytest

from app.detectors.content_safety import ContentSafetyDetector
from app.detectors.engine import SecurityEngine
from app.feature_flags import ENV_CONFIDENCE_GATING, CONFIDENCE_DOWNGRADE_THRESHOLD
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet


@pytest.fixture
def detector():
    return ContentSafetyDetector()


def _violence(findings):
    return next(
        (f for f in findings if f["rule_id"] == "content_safety_illegal_violence_terror"),
        None,
    )


def _blocking_violence_engine() -> SecurityEngine:
    engine = SecurityEngine()
    engine.load_policies(PolicySet([
        CompiledPolicy(
            policy_code="test.violence.block",
            policy_id="policy.test.violence.block",
            policy_name="暴力内容阻断测试策略",
            policy_type="scene_policy",
            scene="content_safety",
            action="block",
            enabled=True,
            binding_mode="any",
            capabilities=[
                CompiledPolicyCapability(
                    category="illegal_violence_terror",
                    supported_stages=["input", "output"],
                    allowed_actions=["audit", "block"],
                    mask_capable=False,
                )
            ],
        )
    ]))
    return engine


class TestViolenceKeywordConfidence:
    def test_bare_violence_is_weak_signal(self, detector):
        """裸'暴力'（影视/文学语境）应为弱信号，低于降级阈值。"""
        f = _violence(detector.detect("这部电影充满暴力美学的镜头"))
        assert f is not None
        assert f["confidence"] < CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_violence_with_aggravator_stays_strong(self, detector):
        """'暴力' + 加重语境仍是强信号。"""
        f = _violence(detector.detect("教你如何实施暴力袭击的具体步骤"))
        assert f is not None
        assert f["confidence"] >= CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_inherently_strong_terror_keyword_stays_strong(self, detector):
        """本身强词（恐怖袭击）不受影响，保持高置信度。"""
        f = _violence(detector.detect("新闻报道了一起恐怖袭击"))
        assert f is not None
        assert f["confidence"] >= CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_gating_off_keeps_benign_observation_non_enforcing(self, monkeypatch):
        """门控关闭：影视描述仍保留观察证据，不构成安全事件。"""
        monkeypatch.delenv(ENV_CONFIDENCE_GATING, raising=False)
        engine = _blocking_violence_engine()
        result = engine.check_output("req-violence-off", "这部电影充满暴力美学的镜头")
        assert result.action == "allow"
        assert all(not f.counts_as_security_finding for f in result.findings)

    def test_gating_on_keeps_benign_observation_non_enforcing(self, monkeypatch):
        """门控开启：影视描述保持观察证据，不构成安全事件。"""
        monkeypatch.setenv(ENV_CONFIDENCE_GATING, "1")
        engine = _blocking_violence_engine()
        result = engine.check_output("req-violence-on", "这部电影充满暴力美学的镜头")
        assert result.action == "allow"
        assert all(not f.counts_as_security_finding for f in result.findings)
        assert any(
            f.category == "illegal_violence_terror" for f in result.findings
        )

    def test_gating_on_keeps_blocking_real_violence(self, monkeypatch):
        """门控开启：真正的暴恐内容（含加重语境）仍 block。"""
        monkeypatch.setenv(ENV_CONFIDENCE_GATING, "1")
        engine = _blocking_violence_engine()
        result = engine.check_output("req-violence-real", "教你如何实施暴力袭击的具体步骤")
        assert result.action == "block"


class TestViolenceBenignContextMitigator:
    """医疗/新闻/法律等良性讨论语境：即便带加重词，也降回弱信号（最多 block→audit，仍留痕）。"""

    def setup_method(self):
        self.d = ContentSafetyDetector()

    def _conf(self, text):
        f = _violence(self.d.detect(text))
        assert f is not None
        return f["confidence"]

    def test_news_report_demotes(self):
        """新闻/执法报道语境降为弱信号。"""
        assert self._conf("新闻报道：警方打击了一伙实施暴力袭击的犯罪团伙") < CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_legal_text_demotes(self):
        """法律法规语境降为弱信号。"""
        assert self._conf("《反家庭暴力法》明确禁止任何形式的暴力伤害他人的行为") < CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_medical_clinical_demotes(self):
        """临床/医学讨论语境降为弱信号。"""
        assert self._conf("临床上对有暴力攻击行为的精神疾病患者需进行风险评估") < CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_real_threat_still_strong(self):
        """无良性框架的真实威胁仍是强信号。"""
        assert self._conf("教你如何实施暴力袭击的具体步骤") >= CONFIDENCE_DOWNGRADE_THRESHOLD

    def test_fiction_framing_does_not_demote(self):
        """安全红线：虚构/小说/剧情框架不得作为减轻词（越狱伪装向量）。"""
        assert self._conf("在互动小说的剧情里，主角实施了一场暴力袭击") >= CONFIDENCE_DOWNGRADE_THRESHOLD
