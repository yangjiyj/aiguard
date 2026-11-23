import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "deploy/migrations/133_fix_passport_regex_escaping.sql"


class PassportRegexMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        match = re.search(
            r"\$passport_regex\$(.*?)\$passport_regex\$",
            cls.sql,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError("迁移必须用 passport_regex 美元引号保存正则")
        cls.pattern = re.compile(match.group(1))

    def test_only_updates_builtin_system_passport_rule(self):
        for expected in (
            "rule_set.id = 'ruleset_builtin_generic'",
            "rule_set.tenant_id = 'tenant_system'",
            "rule_set.source_type = 'builtin'",
            "rule.id = 'rule_g_passport'",
        ):
            self.assertIn(expected, self.sql)

    def test_rejects_lowercase_internal_identifier(self):
        self.assertIsNone(self.pattern.search("d212345654"))

    def test_accepts_uppercase_passport(self):
        self.assertIsNotNone(self.pattern.search("E12345678"))

    def test_rejects_match_inside_longer_alphanumeric_identifier(self):
        self.assertIsNone(self.pattern.search("XYE12345678Z9"))


if __name__ == "__main__":
    unittest.main()
