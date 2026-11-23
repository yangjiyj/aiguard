import pytest

from app.detectors.pii_checksum import validate_bank_card, validate_id_card_cn


def test_valid_id_card():
    # 11010519491231002X：GB11643 加权和 % 11 == 2 -> 校验位 X
    assert validate_id_card_cn("11010519491231002X") is True


def test_invalid_id_card_checkbit():
    # 12345678901234567X：加权和 % 11 == 5 -> 应为 7，与 X 不符
    assert validate_id_card_cn("12345678901234567X") is False


def test_id_card_wrong_length():
    assert validate_id_card_cn("1101051949123100") is False
    assert validate_id_card_cn("") is False


def test_valid_bank_card_16():
    assert validate_bank_card("6222600000000006") is True


def test_valid_bank_card_19():
    assert validate_bank_card("6222600000000000008") is True


def test_invalid_bank_card_luhn():
    assert validate_bank_card("6222021234567890123") is False


def test_bank_card_non_digit_or_length():
    assert validate_bank_card("abcd") is False
    assert validate_bank_card("123") is False


class TestChecksumDropInvalid:
    """校验位失败即丢弃：Luhn/GB11643 不过的纯数字串（流水号/时间戳/遥测 ID）不生成 finding。

    开关 SECURITY_PII_CHECKSUM_DROP_INVALID 默认开；显式关闭时回退旧行为（conf 0.3 留痕）。
    仅在 SECURITY_PII_CHECKSUM_ENABLED 开启时生效。
    """

    def _engine(self, monkeypatch, drop: str = None):
        monkeypatch.setenv("SECURITY_PII_CHECKSUM_ENABLED", "1")
        if drop is None:
            monkeypatch.delenv("SECURITY_PII_CHECKSUM_DROP_INVALID", raising=False)
        else:
            monkeypatch.setenv("SECURITY_PII_CHECKSUM_DROP_INVALID", drop)
        from app.detectors.engine import SecurityEngine
        return SecurityEngine()

    def test_luhn_fail_bank_card_dropped(self, monkeypatch):
        eng = self._engine(monkeypatch)
        result = eng.check_input("req-drop-bank", "订单号 1234567890123456")
        assert all(f.category != "bank_card_cn" for f in result.findings)

    def test_luhn_pass_bank_card_kept_high_confidence(self, monkeypatch):
        eng = self._engine(monkeypatch)
        result = eng.check_input("req-keep-bank", "卡号 4111111111111111")
        hits = [f for f in result.findings if f.category == "bank_card_cn"]
        assert hits
        assert hits[0].severity == "high"
        assert hits[0].confidence == 0.95

    def test_checkbit_fail_id_card_dropped(self, monkeypatch):
        eng = self._engine(monkeypatch)
        result = eng.check_input("req-drop-id", "编号 12345678901234567X")
        assert all(f.category != "id_card_cn" for f in result.findings)

    def test_checkbit_pass_id_card_kept_high_confidence(self, monkeypatch):
        eng = self._engine(monkeypatch)
        result = eng.check_input("req-keep-id", "身份证 11010519491231002X")
        hits = [f for f in result.findings if f.category == "id_card_cn"]
        assert hits
        assert hits[0].severity == "high"
        assert hits[0].confidence == 0.95

    def test_drop_disabled_keeps_legacy_low_confidence_finding(self, monkeypatch):
        eng = self._engine(monkeypatch, drop="0")
        result = eng.check_input("req-legacy-bank", "订单号 1234567890123456")
        hits = [f for f in result.findings if f.category == "bank_card_cn"]
        assert hits
        assert hits[0].confidence == 0.3

    def test_checksum_master_off_drop_has_no_effect(self, monkeypatch):
        """主开关关闭时行为与改造前一致：不校验、conf 0.95。"""
        monkeypatch.delenv("SECURITY_PII_CHECKSUM_ENABLED", raising=False)
        monkeypatch.delenv("SECURITY_PII_CHECKSUM_DROP_INVALID", raising=False)
        from app.detectors.engine import SecurityEngine
        eng = SecurityEngine()
        result = eng.check_input("req-master-off", "订单号 1234567890123456")
        hits = [f for f in result.findings if f.category == "bank_card_cn"]
        assert hits
        assert hits[0].confidence == 0.95

    def test_phone_and_email_unaffected(self, monkeypatch):
        eng = self._engine(monkeypatch)
        result = eng.check_input("req-phone-email", "手机 13812345678 邮箱 test@example.com")
        cats = {f.category for f in result.findings}
        assert "phone_cn" in cats
        assert "email" in cats

    def test_drop_invalid_flag_default_on(self, monkeypatch):
        from app import feature_flags as ff
        ff.apply_overrides({})
        monkeypatch.delenv(ff.ENV_PII_CHECKSUM_DROP_INVALID, raising=False)
        assert ff.is_enabled_default_on(ff.ENV_PII_CHECKSUM_DROP_INVALID) is True
        for v in ("0", "false", "no", "off"):
            monkeypatch.setenv(ff.ENV_PII_CHECKSUM_DROP_INVALID, v)
            assert ff.is_enabled_default_on(ff.ENV_PII_CHECKSUM_DROP_INVALID) is False
        for v in ("1", "true", "yes", "on"):
            monkeypatch.setenv(ff.ENV_PII_CHECKSUM_DROP_INVALID, v)
            assert ff.is_enabled_default_on(ff.ENV_PII_CHECKSUM_DROP_INVALID) is True


class TestBuiltinRulePackChecksumValidation:
    @staticmethod
    def _engine(monkeypatch):
        monkeypatch.setenv("SECURITY_PII_CHECKSUM_ENABLED", "1")
        monkeypatch.setenv("SECURITY_PII_CHECKSUM_DROP_INVALID", "1")
        from app.detectors.engine import SecurityEngine
        from app.custom_rules import CompiledRule

        engine = SecurityEngine()
        engine.load_custom_rules([
            CompiledRule(
                rule_id="rule_g_bankcard",
                rule_name="银行卡号",
                rule_type="regex",
                category="pii_bankcard",
                severity="high",
                action="audit",
                regex=r"(?<!\d)[3-6]\d{15,18}(?!\d)",
            ),
            CompiledRule(
                rule_id="rule_g_phone",
                rule_name="手机号",
                rule_type="regex",
                category="pii_phone",
                severity="medium",
                action="audit",
                regex=r"1[3-9]\d{9}",
            ),
        ])
        return engine

    @pytest.mark.parametrize("stage", ["input", "output"])
    def test_invalid_luhn_from_builtin_rule_pack_is_dropped(
        self, monkeypatch, stage
    ):
        engine = self._engine(monkeypatch)
        if stage == "input":
            result = engine.check_input(
                "req-custom-bank-input",
                "Claude Code 内部编号 4756138564441249",
                skip_semantic=True,
                agent_type="claude-code",
                content_source="tool_result",
            )
        else:
            result = engine.check_output(
                "req-custom-bank-output",
                "Claude Code 内部编号 4756138564441249",
            )
        assert {finding.rule_id for finding in result.findings}.isdisjoint(
            {"rule_g_bankcard", "rule_g_phone"}
        )

    def test_valid_luhn_from_builtin_rule_pack_is_kept(self, monkeypatch):
        engine = self._engine(monkeypatch)
        result = engine.check_input(
            "req-custom-bank-valid",
            "卡号 4111111111111111",
        )
        assert any(f.rule_id == "rule_g_bankcard" for f in result.findings)
