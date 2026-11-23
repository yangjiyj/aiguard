"""2026-11-20 客户现场：涉密文件标记检测把“描述网关规则的那句话”当成密级标记，形成死循环。

现场：Claude Code 被网关拦过一次后，压缩上下文生成的会话摘要里写着
  - Security gateway blocks any tool call/output containing the "CONFIDENTIAL" classification marker.
旁边恰好有 "Files and Code Sections"、docs/design.md 这类文件词，英文规则的近邻佐证成立，
于是此后每次请求都带着这段摘要被拦，一夜 171 次。另一位员工的工具说明里“不要把机密内容放进提示词”
也被拦（中文“机密”+“内容”在标记语法位置）。

判法（只作用于这一处出现，同一段里另有真实标记照样命中）：
- 引号里的密级词 + 紧跟“标记/字样/marker/label”这类名词 + 同一句里有网关/拦截/检测语境 → 是在谈规则，不是标记；
- 紧跟在“不要把/禁止将/切勿”这类叮嘱之后的密级词 → 是提醒，不是标记。
"""
from app.detectors.data_leak import DataLeakDetector
from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

det = DataLeakDetector()
CLASSIFIED = {"classified_classified_cn", "classified_classified_en"}

SITE_SUMMARY = (
    "2. Key Technical Concepts:\\n     - GitLab (gitlab.example.cn); MR workflow; SSH remote (HTTP needs PAT/2FA).\\n"
    "     - Security gateway blocks any tool call/output containing the \\\"CONFIDENTIAL\\\" classification marker.\\n"
    "  \\n  3. Files and Code Sections:\\n     - `docs/design.md` (v0.5) and `docs/tools.md` (v0.4): design docs for the probe."
)


def _classified(text):
    return [f for f in det.detect(text) if f["category"] in CLASSIFIED]


def test_site_compact_summary_not_flagged():
    assert _classified(SITE_SUMMARY) == []


def test_plain_quotes_variant_not_flagged():
    text = ('The security gateway blocks any tool output containing the "CONFIDENTIAL" classification marker, '
            'so skip that file and continue with docs/design.md.')
    assert _classified(text) == []


def test_chinese_rule_description_not_flagged():
    text = '公司安全网关会拦截任何包含“机密”字样的工具输出，相关文件已跳过，继续看 design 文档。'
    assert _classified(text) == []


def test_chinese_instruction_not_flagged():
    text = ("不读 `~/.codebuddy`、`~/.claude` 下的凭证文件。子进程继承当前环境变量。\\n"
            "- 日志会记录提示词和回复文本。不要把机密内容放进提示词。\\n\\n## 日志\\n每次运行一个文件")
    assert _classified(text) == []


def test_real_marker_after_rule_description_still_flagged():
    text = ('The gateway blocks the "CONFIDENTIAL" classification marker.\n'
            'CONFIDENTIAL - Q3 board report attached, see file below.')
    hits = _classified(text)
    assert hits and hits[0]["matched_location"] != "content[29:41]"


def test_quoted_marker_without_gateway_context_still_flagged():
    assert _classified('This file carries the "CONFIDENTIAL" classification marker for the board report.')


def test_marked_quoted_still_flagged():
    assert _classified('The memo is marked "Confidential", see the attached file.')


def test_instruction_then_real_chinese_marker_still_flagged():
    assert _classified('不要把机密文件外传。\n绝密★ 客户名单附件见下')


def test_engine_does_not_block_site_summary():
    policy = CompiledPolicy(
        policy_code="builtin.data_leak.17723b156cfa7533", policy_id="policy-classified",
        policy_name="涉密文件标记检测", policy_type="data_leak", scene="data_security",
        severity="high", action="block", enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=c, supported_stages=["input", "output"], allowed_actions=["audit", "block"], mask_capable=False,
        ) for c in sorted(CLASSIFIED)],
    )
    eng = SecurityEngine()
    eng.load_policies(PolicySet([policy]))
    result = eng.check_input("r1120", SITE_SUMMARY, skip_semantic=True, content_source="user")
    assert not [f for f in result.findings if f.category in CLASSIFIED]
    assert result.action != "block"
