"""2026-11-22 三处漏报：密级标志标头、信用卡安全码缺分隔符、中文“密码是/为/：”明文密码。

每条漏报写“必须报”和“不得误报”两组：误报组在这个检测器近期修过很多，不能回退。
全部样本为自编，卡号为 Luhn 合法的公开测试号，口令为随机现造。
"""
import pytest

from app.detectors.engine import SecurityEngine


@pytest.fixture(scope="module")
def engine():
    return SecurityEngine()


def _cats(engine, text):
    result = engine.check_input("t", text, context={}, content_source="user", skip_semantic=True)
    return {
        (getattr(f, "category", None) or f.type)
        for f in result.findings
        if getattr(f, "counts_as_security_finding", True) is not False
    }


def _classified(engine, text):
    return {c for c in _cats(engine, text) if c.startswith("classified_")}


# ——一、密级标志——
CLASSIFIED_MUST = [
    "机密★10年\n关于某型号芯片流片计划的专题会议纪要",
    "绝密★长期\n某某工程总体方案",
    "秘密★5年\n2026 年度采购预算明细",
    "秘密☆3个月\n某项目阶段评审安排",
    "机密*10年\n某型号芯片流片计划",
    "【机密】某型号芯片流片计划\n一、背景",
    "［绝密］某某工程总体方案\n一、总则",
    "[秘密] 年度采购预算说明\n一、范围",
    "商密★3年\n核心客户报价清单",
    "商业秘密★\n某产品成本构成表",
    "核心商密★长期\n某产品成本构成表",
    "普通商密★2年\n某产品成本构成表",
    "CONFIDENTIAL - DO NOT DISTRIBUTE\nProject roadmap FY27: tape-out schedule",
    "CONFIDENTIAL - INTERNAL ONLY\nProject roadmap FY27: tape-out schedule",
    "STRICTLY CONFIDENTIAL\nProject roadmap FY27: tape-out schedule",
    "TOP SECRET\nProject roadmap FY27: tape-out schedule",
    "INTERNAL USE ONLY\nProject roadmap FY27: tape-out schedule",
    # 保持原有能报
    "文件编号 2026-017  密级：机密  保密期限：10年",
    "内部资料 注意保存\n2026 年度经营分析会材料",
]

CLASSIFIED_MUST_NOT = [
    # 单独一个 CONFIDENTIAL / CLASSIFIED 不算标头（现场模型回复里讲这个标记时就是这样单独一行）
    "CONFIDENTIAL",
    "数据分级取值：\nCONFIDENTIAL\nPUBLIC\nINTERNAL",
    "网关拦的是下面这个词：\n\nCONFIDENTIAL\n\n换个写法就行",
    "CLASSIFIED",
    "机密计算是一种保护使用中数据的技术",
    "Confidential computing protects data in use with hardware enclaves",
    "这是个秘密，别告诉别人",
    "我们都要保守秘密",
    "k8s 的 Secret 对象用来保存口令，注意用 RBAC 限制读取",
    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-conf",
    "the request was classified as error by the router",
    "请不要把机密信息发出来",
    '网关会拦含 "CONFIDENTIAL" 标记的内容',
    "the roadmap is confidential until launch, so keep it quiet",
    "公司保密管理制度要求文件标注密级，帮我写一份培训通知",
    "// Copyright (c) Foo Inc. Proprietary and confidential.\nint main() { return 0; }",
    "【机密计算】技术白皮书的阅读笔记",
    "[机密](https://example.com/glossary) 的定义见词汇表",
    "CONFIDENTIAL COMPUTING CONSORTIUM\nMEMBERS ONLY WEBINAR",
    "CLASSIFIED AS ERROR BY THE ROUTER",
]


@pytest.mark.parametrize("text", CLASSIFIED_MUST)
def test_classified_header_detected(engine, text):
    assert _classified(engine, text), text


@pytest.mark.parametrize("text", CLASSIFIED_MUST_NOT)
def test_classified_discussion_not_flagged(engine, text):
    assert not _classified(engine, text), (text, _classified(engine, text))


# ——二、信用卡安全码——
CVV_MUST = [
    "卡号 4111 1111 1111 1111 有效期 12/27 CVV 123",
    "信用卡背面安全码 123，卡号 4111111111111111",
    "卡号 4111111111111111 CVV2: 123",
    "卡号 4111111111111111 CVC 123",
    "卡号 4111111111111111 安全码 123",
    "卡号 4111111111111111 安全码：123",
    "CVV：123 卡号 4111 1111 1111 1111",
    "CVV：123",  # 原有：无卡号降中危但仍计入
]
CVV_MUST_NOT = [
    "CVV 字段必须是 3 位数字",
    "校验 cvv 长度 3",
    "安全码 123",
    "请输入 123 作为测试",
    "卡号 4111111111111111\n\n另一件事：安全码 123 是门禁的",
]


@pytest.mark.parametrize("text", CVV_MUST)
def test_cvv_detected(engine, text):
    assert "credit_card_cvv" in _cats(engine, text), text


@pytest.mark.parametrize("text", CVV_MUST_NOT)
def test_cvv_not_flagged(engine, text):
    assert "credit_card_cvv" not in _cats(engine, text), text


# ——三、中文明文密码——
PWD_MUST = [
    "生产库 root 密码是 Xk9#mP2$vL8qRt",
    "数据库密码为 Xk9#mP2$vL8qRt，别外传",
    "root 密码：Xk9#mP2$vL8qRt",
    "root 密码:Xk9#mP2$vL8qRt",
    "跳板机口令是 Xk9#mP2$vL8qRt",
    "跳板机口令为 Xk9#mP2$vL8qRt",
    "ssh 登录 root@10.2.3.4 password=Xk9#mP2$vL8qRt",
]
PWD_MUST_NOT = [
    "密码是什么",
    "密码是否正确",
    "密码是必填项",
    "密码为空时报错",
    "密码：<请填写>",
    "密码是 xxx",
    "密码是******",
    "把密码改成从环境变量读取",
    "用户忘记密码是常见问题，需要提供找回流程",
    "密码为空时报错并提示用户重新输入正确的密码",
    "口令是一种身份鉴别方式",
]


@pytest.mark.parametrize("text", PWD_MUST)
def test_plain_password_detected(engine, text):
    assert "plain_password" in _cats(engine, text), text


@pytest.mark.parametrize("text", PWD_MUST_NOT)
def test_plain_password_not_flagged(engine, text):
    assert "plain_password" not in _cats(engine, text), text


# ——复核补充：c3372c57f 新引入的误报，以及必须继续报的写法——
REVIEW_NEW_FP_CLASSIFIED = [
    "这是个**秘密**，别告诉别人，帮我写个生日惊喜方案文件",
    "密级分三档：\n- **绝密**：最高\n- **机密**：其次\n- **秘密**：最低\n请据此写一份保密制度文件",
    "变量名 secret* 和 机密* 开头的字段都要脱敏，帮我改这个文件",
    "README\nCLASSIFIED ADS MODULE\nThis module handles classified ads listing.",
    "CONFIDENTIAL COMPUTING OVERVIEW",
    "INTERNAL USE CASES",
]


@pytest.mark.parametrize("text", REVIEW_NEW_FP_CLASSIFIED)
def test_review_classified_new_fp(engine, text):
    assert not _classified(engine, text), (text, _classified(engine, text))


def test_review_bold_confidential_computing_adds_no_cn(engine):
    # 基线只有 classified_en，不应新增 classified_cn
    got = _classified(engine, "**机密**计算（confidential computing）是什么？给我一份资料")
    assert "classified_classified_cn" not in got, got


def test_review_password_with_cjk_connector_not_flagged(engine):
    assert "plain_password" not in _cats(engine, "密码是否正确请检查一下输入Abc123xyz")


@pytest.mark.parametrize("text", [
    "密码是不是 Xk9#mP2$vL8qRt",
    "密码是什么 Xk9#mP2$vL8qRt",
    "密码是从 Xk9#mP2$vL8qRt 读的",
    "密码为空 Xk9#mP2$vL8qRt",
])
def test_review_password_connector_excluded(engine, text):
    assert "plain_password" not in _cats(engine, text), text


def test_review_cvv_label_alone_with_number_not_flagged(engine):
    assert "credit_card_cvv" not in _cats(engine, "安全码 2026 是活动口令，订单号 6222021234567890123")


REVIEW_STILL_MUST = [
    ("机密★10年\n会议纪要", "classified_"),
    ("【绝密】某某方案", "classified_"),
    ("STRICTLY CONFIDENTIAL\nBoard minutes", "classified_"),
    ("TOP SECRET//NOFORN\nOps plan", "classified_"),
    ("秘密*5年\n采购预算", "classified_"),
    ("CONFIDENTIAL - DO NOT DISTRIBUTE\nProject roadmap", "classified_"),
    ("root 密码是 Xk9#mP2$vL8qRt", "plain_password"),
    ("卡号 4111 1111 1111 1111 CVV 123", "credit_card_cvv"),
    ("信用卡背面安全码 123，卡号 4111111111111111", "credit_card_cvv"),
]


@pytest.mark.parametrize("text,prefix", REVIEW_STILL_MUST)
def test_review_still_detected(engine, text, prefix):
    assert any(c.startswith(prefix) for c in _cats(engine, text)), text
