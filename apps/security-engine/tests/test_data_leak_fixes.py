"""data_leak classified 修缮：单词降档 + 需佐证；编码流量降级。"""
from app.detectors.data_leak import DataLeakDetector
from app.detectors.engine import SecurityEngine

det = DataLeakDetector()


def _find(text, rule_id):
    return next((f for f in det.detect(text) if f["rule_id"] == rule_id), None)


def test_classified_with_corroboration_high_confidence():
    # 真实涉密外泄：机密 + 文档/数据语境 → high、高置信
    f = _find("这是机密文件，包含客户名单和财务数据", "data_leak_classified_cn")
    assert f is not None
    assert f["severity"] == "high"
    assert f["confidence"] >= 0.85


def test_classified_bare_word_low_confidence():
    # 单词"机密"无文档语境，不是涉密文件外发证据。
    assert _find("他说这话有点机密", "data_leak_classified_cn") is None


def test_classified_downgraded_in_coding_traffic(monkeypatch):
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-cl-1", "代码注释：这是内部机密文档的字段说明", context={"agent_type": "claude-code"},
        agent_type="claude-code",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_cn"), None)
    assert f is not None
    assert f.severity == "medium"
    assert f.severity_original == "high"


def test_classified_customer_financial_data_not_downgraded_in_coding_traffic(monkeypatch):
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-wb-dlp-1",
        "这是机密文件，包含客户名单和财务数据。",
        context={"agent_type": "workbuddy"},
        agent_type="workbuddy",
        content_source="user",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_cn"), None)
    assert f is not None
    assert f.severity == "high"
    assert f.severity_original is None
    assert f.counts_as_security_finding is True
    assert result.action != "allow"


def test_deepseek_harness_is_coding_agent_classified_downgraded(monkeypatch):
    # DeepSeek Harness 是官方开源编码智能体：与 claude-code 同样走编码流量降级。
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-ds-1", "代码注释：这是内部机密文档的字段说明", context={"agent_type": "deepseek-harness"},
        agent_type="deepseek-harness",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_cn"), None)
    assert f is not None
    assert f.severity == "medium"
    assert f.severity_original == "high"


def test_deepseek_harness_customer_financial_data_not_downgraded(monkeypatch):
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-ds-dlp-1",
        "这是机密文件，包含客户名单和财务数据。",
        context={"agent_type": "deepseek-harness"},
        agent_type="deepseek-harness",
        content_source="user",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_cn"), None)
    assert f is not None
    assert f.severity == "high"
    assert f.severity_original is None
    assert f.counts_as_security_finding is True
    assert result.action != "allow"


# ——① 真实攻击样本仍命中（不漏检）——


def test_english_classified_leak_with_corroboration_still_hits():
    # 真实英文涉密外泄：confidential + document 佐证 → high、高置信，不因降档漏检
    f = _find(
        "Attached is the confidential customer contract document, do not share.",
        "data_leak_classified_en",
    )
    assert f is not None
    assert f["severity"] == "high"
    assert f["confidence"] >= 0.85


def test_classified_category_label_not_flagged_as_leak():
    # 告警/评估摘要里的规则分类名不是涉密文件标记。
    # 生产误报样例：模型输出摘要里包含 classified_classified_en / cn，
    # 旧规则会从分类名中抠出普通单词 classified 并打成高危。
    text = (
        "Handoff summary: gateway evidence categories included "
        "generic_api_key high, classified_classified_cn high, "
        "classified_classified_en high, semantic_instruction_override high."
    )
    assert _find(text, "data_leak_classified_en") is None


def test_ordinary_classified_word_without_local_document_context_not_flagged():
    # 普通英文 classification 用语不是外发密级标记。
    assert _find("The issue is classified as a normal false positive.", "data_leak_classified_en") is None


def test_classified_rule_evidence_discussion_not_flagged_as_leak():
    # 正常 agent 上下文里会出现规则说明/告警证据/历史测试片段，不能因为
    # “数据泄露规则”附近出现“机密”就当成真实涉密文件外发。
    text = (
        "security_events matched_summary: rule_name=涉密文件标记检测, "
        "category=classified_classified_cn, evidence_reason=命中数据泄露classified规则, "
        "raw_evidence=机密, counts_as_security_finding=true"
    )
    assert _find(text, "data_leak_classified_cn") is None


def test_classified_leak_not_downgraded_in_normal_human_traffic(monkeypatch):
    # 非编码流量（无 agent_type/endpoint 画像）：真实涉密外泄不降档，保持 high 留证不漏检
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input("r-hu-1", "这是机密文件，含客户名单和财务数据")
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_cn"), None)
    assert f is not None
    assert f.severity == "high"
    assert f.severity_original is None


# ——② Claude Code / opencode 系统提示词/开发场景文本不再误报——


def test_cc_system_prompt_confidential_wording_not_flagged_as_leak():
    # Claude Code 系统提示词里"treat user data as confidential"是行为约束措辞，
    # 无文档/数据实体佐证 → 弱信号（低置信），交置信度门控降级而非当真外泄。
    text = (
        "You are Claude Code. Always keep the user's information confidential "
        "and never expose secrets."
    )
    assert _find(text, "data_leak_classified_en") is None


def test_opencode_dev_comment_confidential_downgraded_in_coding_traffic(monkeypatch):
    # opencode 编码流量里代码注释 "# mark internal use only" 触发 classified_en，
    # 有 internal use 措辞但纯代码注释：编码流量降级层降至 medium（audit 留痕，不 block）。
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-oc-1",
        "def sync():\n    # internal use only, see the design document\n    return 1",
        context={"agent_type": "opencode"},
        agent_type="opencode",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_en"), None)
    assert f is not None
    assert f.severity == "medium"
    assert f.severity_original == "high"
    # 降档后不构成阻断信号
    assert result.action != "block"


def test_opencode_marker_comment_still_downgraded_in_coding_traffic(monkeypatch):
    # 全大写标头仍是标记：编码流量里照常命中，降级层只降级别。
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    eng = SecurityEngine()
    result = eng.check_input(
        "r-oc-2",
        "def sync():\n    # INTERNAL USE ONLY - see the design document\n    return 1",
        context={"agent_type": "opencode"},
        agent_type="opencode",
    )
    f = next((x for x in result.findings if x.rule_id == "data_leak_classified_en"), None)
    assert f is not None
    assert f.severity == "medium"
    assert f.severity_original == "high"
    assert result.action != "block"
