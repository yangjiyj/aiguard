import unittest,re,json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ReviewDocumentContracts(unittest.TestCase):
 def test_impact_document_has_no_real_account_or_private_ip(self):
  text=(ROOT/'docs/operations/2026-10-12-chat-portal-model-access-impact.md').read_text()
  self.assertNotRegex(text,r'192[.]168[.]56[.]10|examplegw|demo_gateway_proxy_20261009|[|] admin [|]')
 def test_merge_migration_lint_entry_matches_file(self):
  baseline=json.loads((ROOT/'deploy/upgrade/migration-lint-baseline.json').read_text())
  for entry in baseline['entries']:
   if entry['path']=='deploy/migrations/974_user_account_merges.sql':
    self.assertEqual(entry['sha256'],hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
