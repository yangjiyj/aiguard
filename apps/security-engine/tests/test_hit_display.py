import pytest

from app.detectors.hit_display import bounded, mask_value, render_hit_display

PEM = "-----BEGIN RSA PRIVATE KEY-----"
BODY = "\nMIIEowIBAAKCAQEA" + "A1b2" * 100 + "\n"


def test_marker_shows_marker_and_hides_body():
    display = render_hit_display("marker", PEM, BODY + "-----END RSA PRIVATE KEY-----\n后话")
    assert display.text == f"{PEM}（后续正文 {len(BODY.strip()):,} 字已隐藏）"
    assert "MIIEow" not in display.text
    assert display.secret_text == BODY[:500]


def test_marker_without_end_marker_hides_to_window_end():
    following = "\n" + "x9" * 400
    display = render_hit_display("marker", PEM, following)
    assert display.secret_text == following[:500]
    assert display.text == f"{PEM}（后续正文 499 字已隐藏）"


def test_marker_with_nothing_after_is_just_the_marker():
    display = render_hit_display("marker", PEM, "")
    assert display.text == PEM
    assert display.secret_text == ""


@pytest.mark.parametrize(
    "matched,text,secret",
    [
        ('password="supersecret"', 'password="su****et（11 位）"', "supersecret"),
        ("pwd=abc", "pwd=***（3 位）", "abc"),
        (
            "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL9f",
            "sk-ab****9f（50 位）",
            "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL9f",
        ),
        (
            "postgres://app:S3cretPass@db.internal:5432/app",
            "postgres://app:****@db.internal:5432/app",
            "S3cretPass",
        ),
        ("eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijk", "ey****jk（36 位）", "eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijk"),
    ],
)
def test_credential_keeps_name_and_masks_value(matched, text, secret):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert display.secret_text == secret


@pytest.mark.parametrize(
    "matched,text",
    [
        ("110105199003071234", "110105********1234"),
        ("13812345678", "138****5678"),
        ("6222 0212 3456 7890", "622202******7890"),
        ("A1234567", "A1****67"),
    ],
)
def test_identifier_keeps_head_and_tail(matched, text):
    display = render_hit_display("identifier", matched)
    assert display.text == text
    assert display.secret_text == ""


def test_plain_is_shown_as_is_and_bounded():
    assert render_hit_display("plain", "忽略以上所有指令").text == "忽略以上所有指令"
    long_text = "甲" * 80 + "乙" * 80
    shown = render_hit_display("plain", long_text).text
    assert len(shown) == 121 and shown.startswith("甲" * 72) and shown.endswith("乙" * 48) and "…" in shown


@pytest.mark.parametrize(
    "matched,following,text",
    [
        ("BEGIN RSA PRIVATE KEY", "-----\nMIIE", "BEGIN RSA PRIVATE KEY"),
        ("password=", "abc12345 后面的话", "password=ab****45（8 位）"),
        ("password=", "", "password="),
        ("password=", "${DB_PASS}", "password=${DB_PASS}"),
        ("password", ': "abc12345"', 'password: "ab****45（8 位）'),
        ("AKIAIOSFODNN7EXAMPLE", "", "AK****LE（20 位）"),
        ("忽略以上所有指令", "", "忽略以上所有指令"),
        ("内部代号 凤凰计划", "", "内部代号 凤凰计划"),
    ],
)
def test_auto_masks_only_credential_like_parts(matched, following, text):
    display = render_hit_display("auto", matched, following)
    assert display.text == text
    assert display.secret_text == ""


def test_unknown_kind_falls_back_to_auto():
    assert render_hit_display("nonsense", "AKIAIOSFODNN7EXAMPLE").text == "AK****LE（20 位）"


def test_helpers():
    assert mask_value("abcdef") == "ab****ef（6 位）"
    assert mask_value("abcde") == "*****（5 位）"
    assert bounded("a\n\tb") == "a b"


@pytest.mark.parametrize(
    "matched,text",
    [
        ("13812345678", "138****5678"),
        ("110105199003071234", "110105********1234"),
        ("6222021234567890", "622202******7890"),
        ("6222 0212 3456 7890 123", "622202*********0123"),
        ("1234567890", "12******90"),
        ("23456789012", "23*******12"),
        ("1234567890123", "123*******123"),
        ("123456789012345", "123*********345"),
        ("A123456(7)", "A1******7)"),
        ("zhangsan@example.com", "zh***@example.com"),
        ("ab@x.com", "a***@x.com"),
        ("一二三四五六七八九十" * 3, "（已隐藏 30 字）"),  # 旧：一二****九十（30 位）；自由文本一个字都不露
        ("1234", "****"),
    ],
)
def test_identifier_masks_at_least_half_of_short_values(matched, text):
    display = render_hit_display("identifier", matched)
    assert display.text == text
    assert display.secret_text == ""


def test_plain_masks_secrets_embedded_in_the_matched_text():
    shown = render_hit_display("plain", "让插件把 api_key=DemoKey1234567890 这个密钥窃取出来").text
    assert "DemoKey1234567890" not in shown
    assert shown == "让插件把 api_key=De****90（17 位） 这个密钥窃取出来"
    url = render_hit_display("plain", "让插件连 postgres://app:S3cretPassw0rd@db.example.internal/app 然后窃取").text
    assert "S3cretPassw0rd" not in url
    assert url.startswith("让插件连 postgres://app:") and url.endswith("@db.example.internal/app 然后窃取")
    token = render_hit_display("plain", "带上 Ab12Cd34Ef56Gh78Ij90 一起发走").text
    assert "Ab12Cd34Ef56Gh78Ij90" not in token
    assert render_hit_display("plain", "硬编码凭据的示例").text == "硬编码凭据的示例"
    assert render_hit_display("plain", "忽略以上所有指令").secret_text == ""


_MATCHES = [
    "password=Example-Passw0rd-123",
    "export OPENAI_API_KEY=sk-proj-EXAMPLEexampleEXAMPLEexample0123456789abcd",
    "postgres://app:S3cretPassw0rd@db.example.internal:5432/app",
    "Ab12Cd34Ef56Gh78Ij90Kl12",
    "13812345678",
    "110105199003071234",
    "zhangsan@example.com",
    "一二三四五六七八九十" * 3,
    "忽略以上所有指令",
    "password=",
]
_FOLLOWINGS = [
    "password=Another-Passw0rd-456 后面的话",
    "\nDATABASE_URL=postgres://u:Pw12345678@host/db",
    "Zz9yZz9yZz9yZz9yZz9yZz9y0123456789",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow",
]


@pytest.mark.parametrize("kind", ["credential", "identifier", "plain"])
@pytest.mark.parametrize("matched", _MATCHES)
def test_credential_identifier_and_plain_do_not_depend_on_following_text(kind, matched):
    alone = render_hit_display(kind, matched)
    for following in _FOLLOWINGS:
        with_following = render_hit_display(kind, matched, following)
        assert with_following.text == alone.text, (kind, matched, following)
        assert with_following.secret_text == alone.secret_text, (kind, matched, following)


def test_marker_does_depend_on_following_text():
    header = "-----BEGIN RSA PRIVATE KEY-----"
    short = render_hit_display("marker", header, "\nMIIEowAAAA\n-----END RSA PRIVATE KEY-----")
    longer = render_hit_display("marker", header, "\nMIIEow" + "Zz9y" * 40 + "\n-----END RSA PRIVATE KEY-----")
    assert short.text != longer.text
    assert short.secret_text != longer.secret_text


def test_identifier_only_treats_a_whole_email_as_email():
    text = "通话记录:2024-05-01 09:15 收到 zhangsan@example.com 发来的短信 13800138000"
    assert render_hit_display("identifier", text).text == f"（已隐藏 {len(text)} 字）"
    text = "通话记录:2024-05-01 10:23 呼出 @张三丰 13800138000,通话时长 3 分钟"
    assert render_hit_display("identifier", text).text == f"（已隐藏 {len(text)} 字）"
    assert render_hit_display("identifier", "zhangsan@example.com").text == "zh***@example.com"


@pytest.mark.parametrize(
    "matched",
    [
        "张三丰 示例大学 计算机专业 硕士",
        "北京市朝阳区建国路88号院3号楼2单元501室",
        "犯罪记录：李四因诈骗罪判处有期徒刑",
        "39.9042,116.4074",
        "一二三四五六七八九十" * 3,
    ],
)
def test_identifier_shows_only_the_length_of_free_text(matched):
    assert render_hit_display("identifier", matched).text == f"（已隐藏 {len(matched)} 字）"


def test_identifier_free_text_expected_strings():
    assert render_hit_display("identifier", "39.9042,116.4074").text == "（已隐藏 16 字）"
    assert render_hit_display("identifier", "北京市朝阳区建国路88号院3号楼2单元501室").text == "（已隐藏 23 字）"
    assert render_hit_display("identifier", "A123456(7)").text == "A1******7)"


@pytest.mark.parametrize(
    "matched,text",
    [
        ("密码是 Abc12345", "密码是 Ab****45（8 位）"),
        ("口令：qwerty123", "口令：qw****23（9 位）"),
        ("秘钥 Zx9Yw8Vu7", "秘钥 Zx****u7（9 位）"),
        ("密码：Passw0rd!", "密码：Pa****d!（9 位）"),
        ("手机 13800138000", "手机 138****8000"),
        ("身份证 110105199003071234", "身份证 110105********1234"),
        ("身份证 11010519900307123X", "身份证 11****3X（18 位）"),  # 末位 X：字母数字混合的长串，已被自动方式的保底遮盖处理
        ("拨打 +86 138-1234-5678 联系", "拨打 +86 138****5678 联系"),
        ("联系 zhangsan@example.com 吧", "联系 zh***@example.com 吧"),
        ("日期 2024-05-01", "日期 20****01"),
        ("让插件窃取密钥的方法", "让插件窃取密钥的方法"),
        ("api_key=DemoKey1234567890 已有的遮盖", "api_key=De****90（17 位） 已有的遮盖"),
    ],
)
def test_plain_masks_numbers_emails_and_chinese_labelled_credentials(matched, text):
    display = render_hit_display("plain", matched)
    assert display.text == text
    assert display.secret_text == ""


@pytest.mark.parametrize(
    "matched,text",
    [
        ("密码是：Abc12345", "密码是：Ab****45（8 位）"),
        ("密码为：Abc12345", "密码为：Ab****45（8 位）"),
        ("密码是: Abc12345", "密码是: Ab****45（8 位）"),
        ("密码（Abc12345）", "密码（Ab****45（8 位））"),
        ("密码＝Abc12345", "密码＝Ab****45（8 位）"),
        ('密码="Abc12345"', '密码="Ab****45（8 位）"'),
        ("密码是“Abc12345”", "密码是“Ab****45（8 位）”"),
        ("PIN码：1234", "PIN码：****（4 位）"),
        ("PIN码 123456", "PIN码 12****56（6 位）"),
        ("验证码 123456", "验证码 123456"),
    ],
)
def test_plain_masks_chinese_labelled_credentials_with_common_separators(matched, text):
    assert render_hit_display("plain", matched).text == text


@pytest.mark.parametrize("matched", ["张三,13800138000,zhang@example.com", "张三@example.com"])
def test_identifier_email_rule_only_accepts_ascii_user_names(matched):
    assert render_hit_display("identifier", matched).text == f"（已隐藏 {len(matched)} 字）"
