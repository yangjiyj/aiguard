import importlib.util,json,os,subprocess,unittest,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('core',Path(__file__).with_name('semantic_recompute.py'));core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)

@unittest.skipUnless(os.getenv('SEMANTIC_RECOMPUTE_TEST_PG_CONTAINER'),'isolated PostgreSQL fixture required')
class ApplyTests(unittest.TestCase):
 def setUp(self):
  self.schema='semantic_'+uuid.uuid4().hex
  self.command=['docker','exec','-i',os.environ['SEMANTIC_RECOMPUTE_TEST_PG_CONTAINER'],'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-At']
  self.sql('CREATE SCHEMA '+self.schema+'; SET search_path='+self.schema+"; CREATE TABLE security_events(id text,tenant_id text,matched_summary jsonb,effective_severity text,alert_group_id text); CREATE TABLE security_event_occurrences(id text,tenant_id text,alert_group_id text); CREATE TABLE alert_groups(id text); CREATE TABLE alert_inbox(id text); INSERT INTO security_events VALUES('a','t','{}','high',NULL),('b','t','{}','high',NULL);")
 def tearDown(self):self.sql('DROP SCHEMA '+self.schema+' CASCADE;')
 def sql(self,query,check=True):
  return subprocess.run(self.command,input='SET search_path='+self.schema+';'+query,text=True,capture_output=True,check=check)
 def changes(self):
  return [{'table':'security_events','before':{'id':id,'tenant_id':'t','matched_summary':{},'effective_severity':'high','alert_group_id':None},'after':{'matched_summary':{'text':"quoted '$cas$ \\u0041 原始值"},'effective_severity':'low'}} for id in ['a','b']]
 def test_exact_snapshot_atomic_apply_and_literal_boundaries(self):
  self.sql(core.build_apply_sql(self.changes()))
  self.assertIn('low|2',self.sql('SELECT effective_severity,count(*) FROM security_events GROUP BY 1;').stdout)
  self.assertIn('$cas$',self.sql("SELECT matched_summary->>'text' FROM security_events WHERE id='a';").stdout)
 def test_concurrent_change_rolls_back_all_rows(self):
  self.sql("UPDATE security_events SET effective_severity='critical' WHERE id='b';")
  result=self.sql(core.build_apply_sql(self.changes()),check=False)
  self.assertNotEqual(result.returncode,0)
  self.assertIn('a|high',self.sql('SELECT id,effective_severity FROM security_events ORDER BY id;').stdout)
 def test_new_group_occurrence_invalidates_reviewed_group_counters(self):
  guards=[{'tenant_id':'t','group_id':'g','security_events':[],'security_event_occurrences':[]}]
  self.sql("INSERT INTO security_event_occurrences VALUES('new','t','g');")
  result=self.sql(core.build_apply_sql(self.changes(),guards),check=False)
  self.assertNotEqual(result.returncode,0)
  self.assertIn('a|high',self.sql('SELECT id,effective_severity FROM security_events ORDER BY id;').stdout)

if __name__=='__main__':unittest.main()
