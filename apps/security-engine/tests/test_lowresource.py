from app.detectors.lowresource import detect_low_resource


def test_detects_cyrillic_majority():
    sig = detect_low_resource("Привет как дела сегодня утром")
    assert sig is not None
    assert sig.script == "cyrillic"
    assert sig.ratio >= 0.30


def test_ignores_minor_foreign_token_in_english():
    # 绝大多数是 ASCII，个别外文 token 不应命中
    assert detect_low_resource("hello world Привет ok done now") is None


def test_too_few_chars_returns_none():
    assert detect_low_resource("Пр") is None


def test_pure_english_returns_none():
    assert detect_low_resource("this is a normal english sentence") is None


def test_arabic_detected():
    sig = detect_low_resource("مرحبا كيف حالك اليوم يا صديقي")
    assert sig is not None
    assert sig.script == "arabic"
