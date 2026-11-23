"""Run the real orchestration under bounded fakes to prove rollback boundaries."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('rotation_guard_fixture',ROOT/'deploy/maintenance/internal_secret_rotation_guest.py')
rotation=importlib.util.module_from_spec(spec);spec.loader.exec_module(rotation)


class RotationGuardTests(unittest.TestCase):
    def exercise(self, drift=False):
        with tempfile.TemporaryDirectory(prefix='rotation-guards-') as folder:
            root=Path(folder);work=root/'releases/site'
            (work/'bin').mkdir(parents=True);(work/'active-config').mkdir()
            (root/'development-releases').mkdir();(root/'maintenance-backups').mkdir()
            (work/'bin/docker-compose').write_text('fixture')
            old='fixture-old-internal-secret'
            (work/'.env').write_text(rotation.TOKEN_ENV+'='+old+'\n')
            canonical=work/'active-config/original.json'
            rows={};services={}
            for service in (*rotation.TARGETS,'postgres'):
                env=[rotation.TOKEN_ENV+'='+old] if service in rotation.TARGETS else ['POSTGRES_USER=postgres','POSTGRES_DB=fixture']
                rows[service]={'Id':service,'Image':'fixed-image','RestartCount':0,'State':{'Status':'running','StartedAt':'before'},'Config':{'Env':env,'Labels':{'com.docker.compose.project':'fixture','com.docker.compose.project.working_dir':str(work)}},'HostConfig':{'PortBindings':{},'NetworkMode':'bridge'},'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'127.0.0.1'}}}}
                services[service]={'image':'fixed-image','environment':dict(value.split('=',1) for value in env),'pull_policy':'never'}
            model={'name':'fixture','services':services};canonical.write_text(json.dumps(model))
            calls=[];counter={'inspect':0};flags={'rollback':False}
            def inspect(project=None):
                counter['inspect']+=1
                answer=copy.deepcopy(rows)
                if drift and counter['inspect']>1:answer['gateway-core']['Id']='concurrent-change'
                return 'fixture',answer
            def command(argv,**kwargs):
                calls.append(argv)
                if 'config' in argv:
                    return Path(argv[argv.index('-f')+1]).read_text()
                if argv[:4]==['ip','-j','route','show']:return '[{"dev":"eth0"}]'
                if 'psql' in argv:
                    query=kwargs.get('data','')
                    if 'COUNT(*)' in query:return '0\n'
                    if 'json_agg' in query:return '[]\n'
                    if 'SELECT id' in query:return 'ca-fixture\n'
                if 'up' in argv:flags['rollback']=True
                return ''
            def run(argv,**kwargs):
                if 'pg_dump' in argv:kwargs['stdout'].write(b'fixture-backup')
                return subprocess.CompletedProcess(argv,0,stdout='',stderr='')
            vm=SimpleNamespace(resolve_release_compose=lambda *args:((canonical,),(canonical,)))
            clock=itertools.count(0,200)
            with patch.object(rotation,'ROOT',root),patch.object(rotation,'inspect',inspect),patch.object(rotation,'command',command),patch.object(rotation,'http_status',lambda *args:0 if flags['rollback'] else 200),patch.object(rotation,'prepare_rekey',side_effect=RuntimeError('injected_plan_failure')),patch.object(rotation.subprocess,'run',run),patch.object(rotation.time,'monotonic',lambda:next(clock)),patch.object(rotation.time,'sleep',lambda _:None):
                with self.assertRaises(rotation.RotationError) as result:
                    rotation.rotate(True,'fixture-revision',vm,None)
            if drift:
                self.assertEqual(str(result.exception),'preflight_failed_without_service_changes')
                self.assertFalse(any('up' in call or 'stop' in call for call in calls))
                self.assertFalse(any(call[0]=='iptables' for call in calls))
            else:
                self.assertEqual(str(result.exception),'rollback_failed_ingress_remains_fenced')
                self.assertTrue(any('stop' in call for call in calls))
                self.assertFalse(any(call[:2]==['iptables','-D'] for call in calls))
                self.assertFalse(list((root/'maintenance-backups').glob('*/rollback.json')))
            self.assertEqual((work/'.env').read_text(),rotation.TOKEN_ENV+'='+old+'\n')
            self.assertEqual(list((work/'active-config').iterdir()),[canonical])

    def test_preflight_drift_does_not_recreate_services(self):self.exercise(drift=True)
    def test_failed_rollback_verification_keeps_ingress_closed(self):self.exercise()


if __name__=='__main__':unittest.main()
