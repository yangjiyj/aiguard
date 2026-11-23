"""写法变体绕过（2.9.11 开发 VM 实测附录 A/C/K 类）：检测走归一化视图，脱敏落回原文。

每条绕过写法在修复前都不命中（附录"限制"项），修复后：
- 识别出来，且 masked_content 里不残留可拼回明文的数字/零宽片段；
- 前后无关文字原样保留；
- 附录 K 类误报用例仍然不误报。
"""
import re
import time
import unicodedata

import pytest

from app.detectors.engine import SecurityEngine
from app.custom_rules import CompiledRule, CustomRuleSet, validate_and_compile_regex
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, RedactionSettings

ZW = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]
PHONE = "13800138000"
CARD = "6222021234567890128"
ID18 = "110101199003071233"
ID_X = "11010519491231002X"
TAGS = {"phone_cn": "[手机号]", "bank_card_cn": "[银行卡]", "id_card_cn": "[身份证]", "home_address_cn": "[地址]"}


def _policy(category, replacement):
    return CompiledPolicy(
        policy_code=f"test.{category}", policy_id=f"policy-{category}",
        policy_name=category, policy_type="data_leak", scene="data_security",
        severity="high", action="mask", enabled=True, binding_mode="any",
        redaction=RedactionSettings(replacement=replacement),
        capabilities=[CompiledPolicyCapability(
            category=category, supported_stages=["input", "output"],
            allowed_actions=["audit", "mask", "block"], mask_capable=True,
        )],
    )


def _engine(checksum=True):
    eng = SecurityEngine()
    # 与部署默认一致：SECURITY_PII_CHECKSUM_ENABLED=true（docker-compose/.env.example）
    eng.pii_checksum_enabled = checksum
    eng.load_policies(PolicySet([_policy(c, r) for c, r in TAGS.items()]))
    return eng


@pytest.fixture(scope="module")
def engine():
    return _engine()


def _categories(result):
    return {f.category for f in result.findings}


def _assert_masked(result, expected):
    assert result.action == "mask", [(f.category, f.matched_location) for f in result.findings]
    assert result.masked_content == expected


def _digits(text):
    return re.sub(r"\D", "", unicodedata.normalize("NFKC", text))


# ---- 手机号 ----------------------------------------------------------------

PHONE_VARIANTS = [
    "138-0013-8000",
    "138 0013 8000",
    "138.0013.8000",
    "138－0013－8000",
    "138　0013　8000",
    "+8613800138000",
    "+86 13800138000",
    "+86-138-0013-8000",
    "+86 138 0013 8000",
    "8613800138000",
    "86-13800138000",
    "0086 13800138000",
    "008613800138000",
    "１３８００１３８０００",
    "＋８６１３８００１３８０００",
] + [f"138{zw}0013{zw}8000" for zw in ZW] + ["1\u200b3\u200b8\u200b0\u200b0\u200b1\u200b3\u200b8\u200b0\u200b0\u200b0"]


@pytest.mark.parametrize("variant", PHONE_VARIANTS)
@pytest.mark.parametrize("stage", ["input", "output"])
def test_phone_variants_are_masked_on_both_sides(engine, variant, stage):
    text = f"电话 {variant} 请回电"
    if stage == "input":
        result = engine.check_input("req", text, skip_semantic=True)
    else:
        result = engine.check_output("req", text)
    _assert_masked(result, "电话 [手机号] 请回电")
    phone = [f for f in result.findings if f.category == "phone_cn"]
    assert phone and phone[0].raw_evidence == PHONE


@pytest.mark.parametrize("text, expected", [
    ("tel13800138000end", "tel[手机号]end"),
    ("TEL:13800138000", "TEL:[手机号]"),
    ("call13800138000", "call[手机号]"),
    ("13800138000ok", "[手机号]ok"),
    ("手机号码13800138000谢谢", "手机号码[手机号]谢谢"),
])
def test_phone_touching_letters_is_masked(engine, text, expected):
    _assert_masked(engine.check_input("req", text, skip_semantic=True), expected)


def test_bare_86_with_space_is_not_taken_as_country_code(engine):
    # 号码本身照样脱敏，只是 "86 " 不算进区间，不会残留号码数字
    _assert_masked(engine.check_input("req", "电话 86 13800138000 请回电", skip_semantic=True),
                   "电话 86 [手机号] 请回电")


NUMERIC_BENIGN = [
    "订单号 20261105123456789012 已发货",           # K01
    "会议时间 2026-11-05 14:30:00，地点三楼",        # K02
    "当前版本 v2.9.11.20261105，请升级到 2.9.12",   # K03
    "物流单号 1234567890123456",                     # K04
    "时间戳 1793896411796",                          # K05
    "流水 2026110513800138000999 已入账",            # K06
    "编号 12345678901 已登记",                       # A05
    "流水号 6222021234567891",                       # A12
    "单号 9999123456789019",                         # A14
    "服务器地址 192.168.1.10 端口 8080",             # K12
    "电话 138-0013-8000-12 是分机格式",
    "金额 13800138000.5 元",
    "比例 1.3800138000",
    "user_13800138000",
    "a1b2c13800138000",
    "identifier=abc13800138000def",
    "cafe13800138000",
    "BEEF13800138000",
    "0x13800138000",
    "sha 9f8e7d13800138000a1b2c3d4e5f",
    "id=x13800138000_y",
    "请拨打 138 0013 800 查询",
    "统计 5000 3000 4000 2000 件",
    "统计 4173 1752 7506 7299 件",                  # 过 IIN+Luhn 的 4 位数字表
    "序列 4173-1752-7506-7299",
    "数量 158 3200 4500 6000",
    "12 138 0013 8000 合计",
    "86 173 4605 5700 合计",
    "范围 110101 19900307 1234",                     # 校验位错误
    "身份证 32010219900101123x",                      # A08：校验位错误的小写 x
    "IP 10.138.0.13 端口 8000",
]


@pytest.mark.parametrize("text", NUMERIC_BENIGN)
def test_numeric_benign_text_is_not_pii(engine, text):
    for result in (engine.check_input("req", text, skip_semantic=True), engine.check_output("req", text)):
        assert not _categories(result) & {"phone_cn", "bank_card_cn", "id_card_cn"}, text
        assert result.action != "mask"


# ---- 银行卡 ----------------------------------------------------------------

@pytest.mark.parametrize("variant", [
    "6222 0212 3456 7890 128",
    "6222-0212-3456-7890-128",
    "6222　0212　3456　7890　128",
    "６２２２０２１２３４５６７８９０１２８",
    "6222\u200b0212\u200b3456\u200b7890\u200b128",
])
def test_bank_card_grouped_variants_are_masked(engine, variant):
    for result in (engine.check_input("req", f"卡号 {variant} 谢谢", skip_semantic=True),
                   engine.check_output("req", f"卡号 {variant} 谢谢")):
        _assert_masked(result, "卡号 [银行卡] 谢谢")
        card = [f for f in result.findings if f.category == "bank_card_cn"]
        assert card and _digits(card[0].raw_evidence) == _digits(variant)


@pytest.mark.parametrize("text, expected", [
    ("card 4111 1111 1111 1111", "card [银行卡]"),
    ("汇款到 4111-1111-1111-1111", "汇款到 [银行卡]"),
    ("账户：4111 1111 1111 1111，户名张三", "账户：[银行卡]，户名张三"),
    ("6222 0212 3456 7890 128", "[银行卡]"),           # 62 开头 19 位银联格式不要求标签
])
def test_bank_card_grouped_with_context(engine, text, expected):
    _assert_masked(engine.check_input("req", text, skip_semantic=True), expected)


# ---- 身份证 ----------------------------------------------------------------

@pytest.mark.parametrize("variant, canonical", [
    ("110101 19900307 1233", ID18),
    ("110101 1990 0307 1233", ID18),
    ("110101-19900307-1233", ID18),
    ("１１０１０１１９９００３０７１２３３", ID18),
    ("110101\u200b19900307\u200b1233", ID18),
    ("11010519491231002x", "11010519491231002x"),
    ("110105 19491231 002x", "11010519491231002x"),
    ("１１０１０５１９４９１２３１００２Ｘ", ID_X),
    ("１１０１０５１９４９１２３１００２ｘ", "11010519491231002x"),
])
def test_id_card_variants_are_masked(engine, variant, canonical):
    for result in (engine.check_input("req", f"身份证 {variant} 已核验", skip_semantic=True),
                   engine.check_output("req", f"身份证 {variant} 已核验")):
        _assert_masked(result, "身份证 [身份证] 已核验")
        found = [f for f in result.findings if f.category == "id_card_cn"]
        assert found and found[0].raw_evidence == canonical


@pytest.mark.parametrize("text", [
    "卡号 6222 0212 3456 7890 123 谢谢",       # Luhn 不通过
    "身份证 110101 19900307 1234 已核验",       # 校验位错误
    "身份证 １１０１０１１９９００３０７１２３４ 已核验",
])
def test_grouped_or_normalized_numbers_require_checksum_even_when_switch_is_off(text):
    result = _engine(checksum=False).check_input("req", text, skip_semantic=True)
    assert not _categories(result) & {"bank_card_cn", "id_card_cn"}, text


def test_literal_numbers_keep_legacy_behavior_when_checksum_switch_is_off():
    result = _engine(checksum=False).check_input("req", "流水号 6222021234567891", skip_semantic=True)
    legacy = [f for f in result.findings if f.category == "bank_card_cn"]
    assert legacy and legacy[0].confidence == 0.95


# ---- 地址 ------------------------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ("地址：北京市海淀区中关村大街1号院3号楼502室", "地址：[地址]"),
    ("收货地址 上海市浦东新区世纪大道100号2栋301室，联系人李四", "收货地址 [地址]，联系人李四"),
    ("收件地址：广州市天河区体育西路191号中石化大厦B座1201", "收件地址：[地址]"),
    ("住址：杭州市西湖区文三路90号东部软件园2号楼", "住址：[地址]"),
    ("联系地址:深圳市南山区科技园南区高新南一道8号", "联系地址:[地址]"),
    ("通讯地址 成都市武侯区天府大道北段1700号环球中心", "通讯地址 [地址]"),
    ("邮寄地址：南京市鼓楼区汉口路22号", "邮寄地址：[地址]"),
    ("户籍地址：河北省保定市莲池区东风中路36号", "户籍地址：[地址]"),
    ("我家住在北京市海淀区中关村大街1号院3号楼502室，请寄到这里", "我家住在[地址]，请寄到这里"),
    ("家庭住址：上海市浦东新区世纪大道88号1201室", "家庭住址：[地址]"),
    ("地址：北京市海淀区中关村大街\u200b1号院3号楼502室", "地址：[地址]"),
])
def test_address_labels_are_masked(engine, text, expected):
    for result in (engine.check_input("req", text, skip_semantic=True), engine.check_output("req", text)):
        _assert_masked(result, expected)


@pytest.mark.parametrize("text", [
    "我来自北京市海淀区",                                   # A20
    "服务器地址 192.168.1.10 端口 8080",                    # K12
    "服务器地址：北京市海淀区数据中心3号机房",
    "IP地址：10.0.0.1，网关地址：10.0.0.254",
    "邮箱地址：zhang@example.com",
    "请在浏览器地址栏输入网址后回车",
    "中关村大街1号是一个有名的地标，北京市海淀区很多公司都在附近",
    "请填写收货地址，然后提交订单",
    "地址：待定",
    "住址变更需要带户口本到派出所办理",
    "内存地址 0x7ffeeb3c 处发生访问冲突",
    "他家住在哪里我也不知道",
])
def test_address_benign_text_is_not_address(engine, text):
    for result in (engine.check_input("req", text, skip_semantic=True), engine.check_output("req", text)):
        assert "home_address_cn" not in _categories(result), text


# ---- 自定义关键字 ------------------------------------------------------------

def _keyword_engine(*keywords):
    eng = SecurityEngine()
    eng.load_custom_rules([CompiledRule(
        rule_id="rule_kw_lane_a", rule_name="自建关键字", rule_type="keyword",
        category="custom_keyword", severity="high", action="block", enabled=True,
        keywords=list(keywords),
    )])
    return eng


def _keyword_hits(eng, text):
    return [f for f in eng.check_input("req", text, skip_semantic=True).findings if f.rule_id == "rule_kw_lane_a"]


@pytest.mark.parametrize("text, span", [
    ("项目蓝鲸Z9的预算", (2, 6)),
    ("项目蓝鲸 Z9的预算", (2, 7)),          # C13
    ("项目蓝鲸\u200bZ9的预算", (2, 7)),     # C14
    ("项目蓝鲸Ｚ９的预算", (2, 6)),          # C15
    ("项目蓝 鲸 Z9的预算", (2, 8)),
    ("项目蓝鲸　z9的预算", (2, 7)),
    ("项目蓝\u2060鲸\ufeffＺ\u200d9的预算", (2, 9)),
])
def test_keyword_variants_hit_and_map_to_source(text, span):
    hits = _keyword_hits(_keyword_engine("蓝鲸Z9"), text)
    assert hits, text
    assert hits[0].matched_location == f"content[{span[0]}:{span[1]}]"


def test_keyword_defined_with_fullwidth_or_spaces_matches_plain_text():
    assert _keyword_hits(_keyword_engine("蓝鲸Ｚ９"), "项目蓝鲸Z9的预算")
    assert _keyword_hits(_keyword_engine("绝密 项目X"), "这是绝密项目X的资料")
    assert _keyword_hits(_keyword_engine("绝密项目X"), "这是绝密\u200b项目X的资料")  # C05


def test_keyword_english_spaces_keep_meaning():
    eng = _keyword_engine("top secret")
    assert _keyword_hits(eng, "this is TOP SECRET data")
    assert _keyword_hits(eng, "this is ｔｏｐ ｓｅｃｒｅｔ data")
    assert not _keyword_hits(eng, "this is topsecret data")
    assert not _keyword_hits(_keyword_engine("蓝鲸Z9"), "蓝鲸 Z 9 是两个词")  # 英文/数字之间的空格不折叠


# ---- 自定义正则大小写 ---------------------------------------------------------

def test_custom_regex_accepts_inline_ignorecase_flag():
    pattern, error = validate_and_compile_regex(r"(?i)cus-\d{5}")
    assert error is None and pattern is not None
    eng = SecurityEngine()
    eng.load_custom_rules(CustomRuleSet([CompiledRule(
        rule_id="customer", rule_name="编号", rule_type="regex", category="customer",
        severity="high", action="mask", enabled=True, regex=r"(?i)cus-\d{5}",
        scope={"redaction": {"replacement": "[客户编号]"}},
    )]))
    result = eng.check_input("req", "客户 CUS-12345 和 cus-54321、Cus-11111", skip_semantic=True)
    assert result.masked_content == "客户 [客户编号] 和 [客户编号]、[客户编号]"
    scoped, error = validate_and_compile_regex(r"(?i:cus)-\d{5}")
    assert error is None and scoped.search("CUS-12345")


# ---- 性能：100KB 对抗输入不能触发回溯爆炸 --------------------------------------

@pytest.mark.parametrize("unit", ["13-", "86", "1 ", "1\u200b", "１２３４", "a", "a@", "地址：", "6222 "])
def test_numeric_and_email_scan_is_linear_on_100kb_adversarial_text(engine, unit):
    text = (unit * (100 * 1024 // len(unit) + 1))[:100 * 1024]
    started = time.perf_counter()
    engine._detect_regex_pii(text)
    engine.sensitive_data.detect(text)
    assert time.perf_counter() - started < 3.0
