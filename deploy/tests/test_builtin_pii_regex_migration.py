import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "deploy/migrations/134_harden_builtin_phone_bankcard.sql"


class BuiltinPiiRegexMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.patterns = {}
        for name in ("phone", "bankcard"):
            match = re.search(
                rf"\${name}_regex\$(.*?)\${name}_regex\$",
                cls.sql,
                re.DOTALL,
            )
            if match is None:
                raise AssertionError(f"迁移缺少 {name} 命名正则")
            cls.patterns[name] = re.compile(match.group(1))

    def test_only_updates_builtin_system_rules(self):
        for expected in (
            "rule_set.id = 'ruleset_builtin_generic'",
            "rule_set.tenant_id = 'tenant_system'",
            "rule_set.source_type = 'builtin'",
            "rule.id IN ('rule_g_phone', 'rule_g_bankcard')",
        ):
            self.assertIn(expected, self.sql)

    def test_phone_rejects_substring_inside_long_number(self):
        self.assertIsNone(self.patterns["phone"].search("4756138564441249"))

    def test_phone_accepts_standalone_number(self):
        self.assertIsNotNone(self.patterns["phone"].search("手机 13812345678"))

    def test_bankcard_rejects_substring_inside_twenty_digit_identifier(self):
        self.assertIsNone(
            self.patterns["bankcard"].search("47561385644412491234")
        )

    def test_bankcard_accepts_standalone_card_candidate(self):
        self.assertIsNotNone(
            self.patterns["bankcard"].search("卡号 4111111111111111")
        )


if __name__ == "__main__":
    unittest.main()
