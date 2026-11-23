"""Exercise the real maintenance payload against an isolated PostgreSQL container."""
import ast
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]


class AlertRevalidationIntegration(unittest.TestCase):
    def test_preserves_mixed_evidence_and_concurrent_changes(self):
        real_output = subprocess.check_output
        image = real_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'postgres:16-alpine'], text=True).strip()
        name = 'jjdguard-revalidation-test-' + uuid.uuid4().hex[:12]
        # 先回收被杀掉的测试进程留下的孤儿容器；本容器打同一套测试标签（规则见 deploy/tests/lib/test-containers.sh）。
        subprocess.run(['bash', str(ROOT / 'deploy/tests/lib/test-containers.sh'), 'reap'], check=False)
        test_labels = ['--label', 'jjdguard.test.owner_pid=%d' % os.getpid(),
                       '--label', 'jjdguard.test.created=%d' % int(time.time()),
                       '--label', 'jjdguard.test.host=' + socket.gethostname(),
                       '--label', 'jjdguard.test.kind=alert-revalidation']
        container = real_output(['docker', 'run', '--rm', '-d', '--network', 'none', '--name', name,
            '--label', 'com.docker.compose.service=postgres', *test_labels, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', image], text=True).strip()
        base = ['docker', 'exec', '-i', container, 'psql', '-U', 'postgres', '-d', 'postgres', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1']
        def sql(statement):
            return real_output(base, input=statement, text=True)
        def quote(value):
            return "'" + value.replace("'", "''") + "'"
        try:
            for _ in range(100):
                if subprocess.run(['docker', 'exec', container, 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    break
                time.sleep(0.2)
            else:
                self.fail('fixture PostgreSQL unavailable')
            sql('''CREATE TABLE security_events(id text PRIMARY KEY,tenant_id text,severity text,effective_severity text,alert_group_id text,matched_summary jsonb);
CREATE TABLE alert_groups(id text PRIMARY KEY,tenant_id text,severity text,effective_severity text,disposition_class text,occurrence_count integer,body_json jsonb,updated_at timestamptz);
CREATE TABLE alert_inbox(id text PRIMARY KEY,tenant_id text,severity text,type text,title text,body_json jsonb,read_at timestamptz);
CREATE TABLE system_settings(key text PRIMARY KEY,value text);''')
            builtin_verdict = {'type': 'semantic_attack', 'category': 'semantic_roleplay', 'severity': 'high', 'content_source': 'system_prompt', 'message_role': 'system', 'raw_evidence': '<fixture-system-prompt>'}
            user_verdict = {'type': 'semantic_attack', 'category': 'semantic_jailbreak', 'severity': 'high', 'content_source': 'user', 'message_role': 'user', 'raw_evidence': '<fixture-user>'}
            sql("INSERT INTO security_events VALUES('scope-builtin','tenant_default','high','high',NULL," + quote(json.dumps({'findings': [builtin_verdict]})) + "::jsonb);")
            sql("INSERT INTO security_events VALUES('scope-mixed','tenant_default','high','high',NULL," + quote(json.dumps({'findings': [builtin_verdict, user_verdict]})) + "::jsonb);")
            bad = {'category': 'id_card_cn', 'severity': 'critical', 'raw_evidence': '789739705449372800', 'evidence_context': 'sum:789739705449372800'}
            real = {'category': 'openai_key', 'severity': 'critical', 'raw_evidence': '<fictional-fixture>', 'counts_as_security_finding': True}
            for n in range(1, 8):
                findings = [bad, real] if n == 1 else [bad]
                summary = {'findings': findings}
                group = 'g' + str(n)
                sql("INSERT INTO alert_groups VALUES(" + quote(group) + ",'tenant_default','critical','critical','action_required'," + str(2 if n in (1, 6) else 1) + ',' + quote(json.dumps({'matched': summary})) + "::jsonb,now());")
                if n == 4:
                    continue
                sql("INSERT INTO security_events VALUES(" + quote('e' + str(n)) + ",'tenant_default','critical','critical'," + quote(group) + ',' + quote(json.dumps(summary)) + "::jsonb);")
            for ident, findings in [('i5', [bad]), ('i5cached', [real])]:
                body = {'alert_group_id': 'g5', 'severity': 'critical', 'matched': {'findings': findings}}
                sql("INSERT INTO alert_inbox VALUES(" + quote(ident) + ",'tenant_default','critical','security_event','fixture'," + quote(json.dumps(body)) + "::jsonb,NULL);")
            injected = set()
            def isolated_output(args, *a, **kw):
                if args[:3] == ['docker', 'ps', '-q']:
                    return container + '\n'
                statement = kw.get('input', '')
                if 'UPDATE security_events SET' in statement and 'regroup' not in injected:
                    injected.add('regroup')
                    sql("UPDATE security_events SET alert_group_id='g4' WHERE id='e3';")
                result = real_output(args, *a, **kw)
                if "SELECT row_to_json(ag)" in statement:
                    if "ag.id='g2'" in statement and 'member' not in injected:
                        injected.add('member')
                        sql("INSERT INTO security_events VALUES('late','tenant_default','critical','critical','g2'," + quote(json.dumps({'findings': [real]})) + "::jsonb);")
                    if "ag.id='g7'" in statement and 'group' not in injected:
                        injected.add('group')
                        sql("UPDATE alert_groups SET body_json=body_json || '{\"concurrent_review\":true}'::jsonb WHERE id='g7';")
                return result
            source = (ROOT / 'deploy/maintenance/revalidate_alert_evidence.py').read_text()
            tree = ast.parse(source)
            guest = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'GUEST' for t in n.targets))
            modules = ['app.detectors.pii_checksum', 'app.detectors.numeric_context', 'app.detectors.config_evidence', 'app.detectors.data_leak', 'app.detectors.policy_catalog', 'app.alert_evidence_validation']
            sources = [(module, (ROOT/'apps/security-engine'/Path(*module.split('.'))).with_suffix('.py').read_text()) for module in modules]
            with tempfile.TemporaryDirectory(prefix='jjdguard-revalidation-backup-') as backup:
                code = guest.replace('SOURCES', repr(sources)).replace('APPLY', 'True').replace('REVIEW_DECISIONS', '[]').replace('INSPECTION_SCOPE_MODE', repr(None)).replace('/opt/jjdguard/maintenance-backups', backup)
                subprocess.check_output = isolated_output
                try:
                    exec(compile(code, '<real-maintenance-fixture>', 'exec'), {})
                finally:
                    subprocess.check_output = real_output
                self.assertTrue(list(Path(backup).glob('*.jsonl')))
            groups = dict(line.split('|') for line in sql('SELECT id,effective_severity FROM alert_groups ORDER BY id;').splitlines())
            self.assertEqual(groups['g1'], 'critical')
            self.assertEqual(groups['g2'], 'critical')  # fresh member, no stale downgrade
            self.assertEqual(groups['g5'], 'low')
            self.assertEqual(groups['g6'], 'critical')  # missing retained occurrence
            self.assertEqual(groups['g7'], 'critical')  # full-row CAS rejected
            self.assertEqual(sql("SELECT alert_group_id || '|' || severity || '|' || effective_severity FROM security_events WHERE id='e3';").strip(), 'g4|critical|critical')
            self.assertEqual(sql("SELECT severity FROM security_events WHERE id='e5';").strip(), 'critical')
            self.assertEqual(sql("SELECT severity || '|' || (read_at IS NULL)::text FROM alert_inbox WHERE id='i5';").strip(), 'info|true')
            self.assertEqual(sql("SELECT severity FROM alert_inbox WHERE id='i5cached';").strip(), 'critical')
            # Without an explicit scope the builtin verdicts are untouched.
            self.assertEqual(sql("SELECT effective_severity || '|' || (matched_summary->'findings'->0->>'counts_as_security_finding' IS NULL)::text FROM security_events WHERE id='scope-builtin';").strip(), 'high|true')
            with tempfile.TemporaryDirectory(prefix='jjdguard-revalidation-scope-') as backup:
                code = guest.replace('SOURCES', repr(sources)).replace('APPLY', 'True').replace('REVIEW_DECISIONS', '[]').replace('INSPECTION_SCOPE_MODE', repr('live')).replace('/opt/jjdguard/maintenance-backups', backup)
                subprocess.check_output = isolated_output
                try:
                    exec(compile(code, '<real-maintenance-scope-fixture>', 'exec'), {})
                finally:
                    subprocess.check_output = real_output
                backups = list(Path(backup).glob('*.jsonl'))
                self.assertTrue(backups)
                self.assertIn('<fixture-system-prompt>', backups[0].read_text())
            self.assertEqual(sql("SELECT effective_severity || '|' || severity FROM security_events WHERE id='scope-builtin';").strip(), 'low|high')
            builtin_row = json.loads(sql("SELECT matched_summary FROM security_events WHERE id='scope-builtin';"))
            self.assertEqual(builtin_row['findings'][0]['raw_evidence'], '<fixture-system-prompt>')
            self.assertIs(builtin_row['findings'][0]['counts_as_security_finding'], False)
            self.assertEqual(builtin_row['findings'][0]['evidence_revalidation']['status'], 'out_of_scope')
            mixed_row = json.loads(sql("SELECT matched_summary FROM security_events WHERE id='scope-mixed';"))
            self.assertEqual(sql("SELECT effective_severity FROM security_events WHERE id='scope-mixed';").strip(), 'high')
            self.assertEqual(mixed_row['findings_count'], 1)
            self.assertEqual(mixed_row['findings'][1], user_verdict)
            # Administrator explicitly widened the scope: nothing more is withdrawn.
            sql("INSERT INTO system_settings VALUES('inspect_builtin_context','true'); INSERT INTO security_events VALUES('scope-enabled','tenant_default','high','high',NULL," + quote(json.dumps({'findings': [builtin_verdict]})) + "::jsonb);")
            with tempfile.TemporaryDirectory(prefix='jjdguard-revalidation-scope-on-') as backup:
                code = guest.replace('SOURCES', repr(sources)).replace('APPLY', 'True').replace('REVIEW_DECISIONS', '[]').replace('INSPECTION_SCOPE_MODE', repr('live')).replace('/opt/jjdguard/maintenance-backups', backup)
                subprocess.check_output = isolated_output
                try:
                    exec(compile(code, '<real-maintenance-scope-on-fixture>', 'exec'), {})
                finally:
                    subprocess.check_output = real_output
            self.assertEqual(sql("SELECT effective_severity || '|' || (matched_summary->'findings'->0->>'counts_as_security_finding' IS NULL)::text FROM security_events WHERE id='scope-enabled';").strip(), 'high|true')
        finally:
            subprocess.check_output = real_output
            actual = json.loads(real_output(['docker', 'inspect', container], text=True))[0]
            if actual['Name'] != '/' + name or actual['Image'] != image:
                raise RuntimeError('fixture container identity changed; cleanup refused')
            subprocess.run(['docker', 'stop', '-t', '2', container], check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
