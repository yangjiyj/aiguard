"""凭据和自动两种显示方式在别扭输入下不露秘密。

这些用例来自四轮对抗审查：每条都是曾经让秘密露在显示文本里的输入。
"""
import time

import pytest

from app.detectors.hit_display import render_hit_display

JWT = "eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijk"


@pytest.mark.parametrize(
    "matched,text,secret",
    [
        ("token: Bearer abcdef1234567890xyz", "token: Bearer ab****yz（19 位）", "abcdef1234567890xyz"),
        ('password = "with space inside"', 'password = "wi****de（17 位）"', "with space inside"),
        ("password = with space inside", "password = wi****de（17 位）", "with space inside"),
        ("Authorization: Bearer " + JWT, "Authorization: Bearer ey****jk（36 位）", JWT),
        ('password="Abc\\"def123ghi"', 'password="Ab****hi（14 位）"', 'Abc\\"def123ghi'),
        ('{"password":"p4ss\\"w0rd!x"}', '{"password":"p4****!x（12 位）"}', 'p4ss\\"w0rd!x'),
        ('password="unterminated value here', 'password="u****re（24 位）', '"unterminated value here'),
        ("password=abc123def，后面", "password=ab****后面（12 位）", "abc123def，后面"),
        ("password1=hunter22xx", "password1=hu****xx（10 位）", "hunter22xx"),
        ("mytoken=abc12345", "mytoken=ab****45（8 位）", "abc12345"),
        ("s3_access_key_id=AKIAIOSFODNN7EXAMPLE", "s3_access_key_id=AKIAIO****LE（16 位）", "AKIAIOSFODNN7EXAMPLE"),
        ("password=${DB_PASS}", "password=${DB_PASS}", ""),
        ("password=", "password=", ""),
    ],
)
def test_credential_shows_the_field_name_and_one_masked_value(matched, text, secret):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert display.secret_text == secret
    if secret:
        assert secret not in display.text


@pytest.mark.parametrize(
    "matched,text,secret",
    [
        ("postgres://app:p@ss@db:5432/x", "postgres://app:****@db:5432/x", "p@ss"),
        ("redis://:Example-Pass-1@cache.internal:6379/0", "redis://:****@cache.internal:6379/0", "Example-Pass-1"),
        ("postgres://password:Xyz12345@db", "postgres://password:****@db", "Xyz12345"),
        ("postgres://app:@db", "po****db（18 位）", "postgres://app:@db"),
        ("https://example.com", "ht****om（19 位）", "https://example.com"),
        (
            "postgres://app:Secret1@db/app?sslmode=require&password=x9y8",
            "postgres://app:****@db/app?…",
            "postgres://app:Secret1@db/app?sslmode=require&password=x9y8",
        ),
        (
            "https://hooks.example.com/services/T000/B000/XXXXsecret99",
            "https://hooks.example.com/…",
            "https://hooks.example.com/services/T000/B000/XXXXsecret99",
        ),
        ("DATABASE_URL=postgres://app:S3cretPass@db/app", "DATABASE_URL=postgres://app:****@db/app", "S3cretPass"),
    ],
)
def test_credential_connection_strings(matched, text, secret):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert display.secret_text == secret
    for piece in ("p@ss", "Example-Pass-1", "Xyz12345", "Secret1", "x9y8", "XXXXsecret99", "S3cretPass"):
        assert piece not in display.text


CREDENTIAL_LEAK_CASES = [
    ("password=one1 token=two2two2two2", ["one1", "two2two2two2"]),
    ("password=short1 备用 ZXhhbXBsZS1zZWNyZXQx", ["short1", "ZXhhbXBsZS1zZWNyZXQx"]),
    ("password=hunter22 backup Q1w2E3r4T5y6U7i8: x", ["hunter22", "Q1w2E3r4T5y6U7i8"]),
    ("password=hunter22 backup Q1w2E3r4T5y6U7i8=x", ["hunter22", "Q1w2E3r4T5y6U7i8"]),
    ("API_KEY=abcd1234efgh\nDB_PW=hunter22\nJWT_SIGNING=s3cr3t!x", ["abcd1234efgh", "hunter22", "s3cr3t!x"]),
    ("passphrase=hunter22 token=Q1w2E3r4xyz", ["hunter22", "Q1w2E3r4xyz"]),
    ("pass_hint=hunter22 backup", ["hunter22"]),
    ("password=x1y2\nsee http://a.com mysql://root:hunter22@db", ["x1y2", "hunter22"]),
    ("export DB_URL=postgres://app:S3cretPass@db/app", ["S3cretPass"]),
    ("password=hunter22 url=postgres://u:pw99@h", ["hunter22", "pw99"]),
    ("token=abc123xyz see mysql://root:pw99@db", ["abc123xyz", "pw99"]),
    ('api_key="hunter22 mysql://u:pw99@h"', ["hunter22", "pw99"]),
    ("api_key:\nabcd1234", ["abcd1234"]),
    ("api_key:\n  sk1234abcd", ["sk1234abcd"]),
    ("api_key=\r\nabcdefghijkl", ["abcdefghijkl"]),
    ("password: |\n  hunter22", ["hunter22"]),
    ("password=\nQ1w2E3r4=", ["Q1w2E3r4"]),
    ("token:\nabcDEF123456==", ["abcDEF123456"]),
    ("password=a1b2\rDB_PW=hunter22", ["a1b2", "hunter22"]),
    ("password=\ue000hunter22", ["hunter22"]),
    ("password=hunter22\ue000", ["hunter22"]),
    ("aliyun LTAI5tExampleKeyId0001 secret=abcd9876", ["LTAI5tExampleKeyId0001", "abcd9876"]),
    ('"password": "hunter22", "pin": "4321x"', ["hunter22", "4321x"]),
    ("password=abc123;)", ["abc123"]),
    ("password=abc12345 # 注释 hunter22", ["abc12345", "hunter22"]),
]


@pytest.mark.parametrize("matched,pieces", CREDENTIAL_LEAK_CASES, ids=[repr(c[0])[:40] for c in CREDENTIAL_LEAK_CASES])
def test_credential_never_shows_any_part_of_the_value(matched, pieces):
    display = render_hit_display("credential", matched)
    for piece in pieces:
        assert piece not in display.text, display.text
    assert "\ue000" not in display.text
    assert display.secret_text and display.secret_text in matched  # 秘密本体必须是原文的子串，网关才替换得掉
    for piece in pieces:
        if piece not in display.secret_text:
            # 字段名之前的前导文字里被保底扫描遮掉的串，不在取值里；它不进 secret_text，靠网关的前后文保底扫描兜住
            assert matched.index(piece) < matched.index(display.secret_text)


@pytest.mark.parametrize(
    "matched,following,text",
    [
        ("password=", "abc12345，后面的话", "password=ab****45（8 位）"),
        ("password", "=abc123：后面", "password=ab****23（6 位）"),
        ("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG", "", "AK****LE（20 位）:wJ****NG（21 位）"),
        ("key sk-abcdef1234567890xyz: hello", "", "key sk****yz（22 位）: hello"),
        ("Q1w2E3r4T5y6U7i8 = 1", "", "Q1****i8（16 位） = 1"),
        ('password="a\\"b c"', "", 'password="a\\**** c（6 位）"'),
        ("bypass=true 调试", "", "bypass=true 调试"),
        ("参考 https://example.com/docs 的说明", "", "参考 https://example.com/docs 的说明"),
        ("标题: 内容 password=abc12345", "", "标题: 内容 password=ab****45（8 位）"),
        ("DATABASE_URL=postgres://app:S3cretPass@db", "", "DATABASE_URL=postgres://app:****@db"),
    ],
)
def test_auto_masks_only_what_it_recognises(matched, following, text):
    assert render_hit_display("auto", matched, following).text == text


AUTO_LEAK_CASES = [
    ("见 mysql://root:hunter22@db1 和 redis://:Example-Pass-1@cache", ["hunter22", "Example-Pass-1"]),
    ("a://b://user:Pw1234@h", ["Pw1234"]),
    ('api_key="hunter22 mysql://u:pw99@h"', ["hunter22", "pw99"]),
    ("password:\nabcd1234", ["abcd1234"]),
    ("password=\ue000hunter22", ["hunter22"]),
    ("password=one1secret token=two2two2", ["one1secret", "two2two2"]),
]


@pytest.mark.parametrize("matched,pieces", AUTO_LEAK_CASES, ids=[repr(c[0])[:40] for c in AUTO_LEAK_CASES])
def test_auto_never_shows_a_recognised_secret(matched, pieces):
    display = render_hit_display("auto", matched)
    for piece in pieces:
        assert piece not in display.text, display.text
    assert "\ue000" not in display.text
    assert display.secret_text == ""


def test_private_use_character_in_input_keeps_secret_text_a_substring_of_the_original():
    original = "password=\ue000hunter22"
    assert render_hit_display("credential", original).secret_text == original


def test_rendering_stays_fast_on_long_input():
    payloads = [
        "a" * 50000, "password" * 6250, "a://" + "b" * 50000, 'password="' + "x" * 50000,
        "token: " + "Bearer " * 7000, "a1" * 25000 + "=", "password=:" * 5000,
        "a1" * 25000 + "'" + " " * 50000, "a://u:p@h " * 5000, "a=b\n" * 12500, "://" * 16000,
    ]
    for kind in ("credential", "auto"):
        for payload in payloads:
            started = time.perf_counter()
            render_hit_display(kind, payload)
            assert time.perf_counter() - started < 2.0, (kind, payload[:20])


SECRET_ENDING_WITH_EQUALS = "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9a="


@pytest.mark.parametrize(
    "matched,text",
    [
        (SECRET_ENDING_WITH_EQUALS, "Q1****a=（40 位）"),
        ("Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9==", "Q1****==（40 位）"),
        ("Q1w2E3r4T5y6U7i8O9p0=A1s2D3f4G5h6J7k8L9zz", "Q1****zz（41 位）"),
    ],
)
def test_a_secret_containing_equals_is_not_mistaken_for_a_field_name(matched, text):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert display.secret_text == matched


@pytest.mark.parametrize(
    "matched,pieces",
    [
        ('secret_key = "your_key hunter22"', ["hunter22"]),
        ('api_key="{{ vault }} hunter22"', ["hunter22"]),
        ("password=<prod> Q1w2E3r4T5", ["Q1w2E3r4T5"]),
        ("password=env(X) hunter22", ["hunter22"]),
        ('secret_key = "hunter22_here"', ["hunter22_here"]),
        ("password=<Q1w2E3r4>", ["Q1w2E3r4"]),
    ],
)
def test_text_that_only_starts_like_a_placeholder_is_still_masked(matched, pieces):
    # 自动方式的裸值遇空白就结束（规格写明的局限），所以空白之后的内容只在凭据方式下断言。
    kinds = ("credential", "auto") if '"' in matched or " " not in matched else ("credential",)
    for kind in kinds:
        display = render_hit_display(kind, matched)
        for piece in pieces:
            assert piece not in display.text, (kind, display.text)


@pytest.mark.parametrize(
    "matched",
    [
        "password=${DB_PASS}", "password=$DB_PASS", "password=%DB_PASS%", "password={{vault.db}}",
        "password=<your-password>", "password=changeme", "token=os.getenv('TOKEN')",
        "api_key=process.env.API_KEY", "api_key=your_api_key", 'password=os.environ["DB_PASS"]',
    ],
)
def test_real_placeholders_are_shown_as_is(matched):
    # 自动方式的裸值遇引号就结束，带引号或括号的写法在自动方式下会被多遮，不在这里断言。
    kinds = ("credential",) if "'" in matched or '"' in matched else ("credential", "auto")
    for kind in kinds:
        display = render_hit_display(kind, matched)
        assert display.text == matched, (kind, display.text)
        assert display.secret_text == ""


@pytest.mark.parametrize(
    "matched,text,pieces",
    [
        ("https://hunter22token@github.com/org/repo", "https://hu****en（13 位）@github.com/…", ["hunter22token"]),
        (
            "https://u:pw99@h/api/token/Q1w2E3r4T5y6U7i8",
            "https://u:****@h/a****i8（27 位）",
            ["pw99", "Q1w2E3r4T5y6U7i8"],
        ),
        (
            "postgres://ghp_EXAMPLEexampleEXAMPLE0123:pw99@h/db",
            "postgres://gh****23（29 位）:****@h/db",
            ["ghp_EXAMPLEexampleEXAMPLE0123", "pw99"],
        ),
    ],
)
def test_tokens_in_the_user_name_or_path_of_a_connection_string(matched, text, pieces):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert display.secret_text == matched
    for piece in pieces:
        assert piece not in display.text


def test_auto_masks_a_yaml_block_value():
    display = render_hit_display("auto", "password: |\n  hunter22")
    assert "hunter22" not in display.text
    assert display.text == "password: |   hu****22（8 位）"


@pytest.mark.parametrize(
    "matched,text",
    [
        ("postgres://dbhost?password=hunter22", "postgres://dbhost?…"),
        ("redis://h:6379?auth=hunter22", "redis://h:6379?…"),
        ("postgres://h?user=a@b&password=hunter22", "postgres://…"),
        ("mysql://u:pw99@h?sslpassword=hunter22", "mysql://u:****@h?…"),
        ("postgres://u:pw99@h#frag=hunter22", "postgres://u:****@h?…"),
        ("postgres://dbhost/db?password=hunter22", "postgres://dbhost/…"),
        ("connection='postgres://dbhost?password=hunter22'", "connection='postgres://dbhost?…'"),
    ],
)
def test_connection_string_parameters_are_never_shown(matched, text):
    display = render_hit_display("credential", matched)
    assert display.text == text
    assert "hunter22" not in display.text and "pw99" not in display.text
    assert "hunter22" in display.secret_text  # 参数里的密码必须在秘密本体里，网关才会在前后文里隐藏它


@pytest.mark.parametrize("matched", ['password="$uperS3cret"', "password=$ecurity2024", "password=%Pass1%"])
def test_a_real_password_starting_with_dollar_or_percent_is_masked(matched):
    for kind in ("credential", "auto"):
        display = render_hit_display(kind, matched)
        for piece in ("uperS3cret", "ecurity2024", "Pass1"):
            assert piece not in display.text, (kind, display.text)


def test_text_before_the_field_name_is_swept_even_when_the_value_is_a_placeholder():
    display = render_hit_display("credential", "AWS AKIAIOSFODNN7EXAMPLE secret=xxxxxxxxxxxxxxxx")
    assert display.text == "AWS AK****LE（20 位） secret=xxxxxxxxxxxxxxxx"
    assert display.secret_text == "AWS AKIAIOSFODNN7EXAMPLE secret=xxxxxxxxxxxxxxxx"  # 扫出了长串：整段命中都要从前后文里隐藏


def test_secret_text_covers_a_token_found_before_the_field_name():
    matched = "aliyun LTAI5tExampleKeyId0001 secret=abcd9876"
    display = render_hit_display("credential", matched)
    assert display.text == "aliyun LT****01（22 位） secret=ab****76（8 位）"
    assert display.secret_text == matched


UNENCODED_PASSWORDS = [
    ("postgres://admin:Secr3t#2024@db/app", "postgres://…", ["Secr3t", "2024"]),
    ("postgres://admin:Secr3t?2024@db/app", "postgres://…", ["Secr3t", "2024"]),
    ("postgres://admin:Ab/cD3fGh@db/app", "postgres://…", ["Ab/", "cD3fGh"]),
    ("mysql://root:P@ss#w0rd@db:3306/x", "mysql://…", ["ss", "w0rd"]),
    ("DATABASE_URL=postgres://admin:Secr3t#2024@db/app", "DATABASE_URL=postgres://…", ["Secr3t", "2024"]),
]


@pytest.mark.parametrize("matched,text,pieces", UNENCODED_PASSWORDS)
def test_connection_string_password_with_unencoded_delimiters(matched, text, pieces):
    display = render_hit_display("credential", matched)
    assert display.text == text
    for piece in pieces:
        assert piece not in display.text
    assert display.secret_text.endswith("@db/app") or display.secret_text.endswith("@db:3306/x")
    auto = render_hit_display("auto", matched)
    for piece in pieces:
        assert piece not in auto.text, auto.text


def test_a_value_that_merely_contains_scheme_separator_is_masked_whole():
    display = render_hit_display("credential", "password=Q1w2://hunter22")
    assert display.text == "password=Q1****22（15 位）"
    assert display.secret_text == "Q1w2://hunter22"
