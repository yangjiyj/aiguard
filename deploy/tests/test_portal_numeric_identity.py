# Numeric portal identity must survive rebuilding on the pinned Node image.
import copy, importlib.util, json, os, subprocess, sys, tempfile, unittest, uuid
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('portal_numeric_builder',ROOT/'deploy/release/build_vm_development.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


def output(uid=4242,gid=4343,groups='4343 4444',user='fixtureportal',passwd_gid=4343):
    return f'''uid={uid}
gid={gid}
groups={groups}
passwd=root:0:0
passwd={user}:{uid}:{passwd_gid}
group=root:0
group=fixtureportal:4343
group=fixtureshare:4444
'''


class NumericIdentityTests(unittest.TestCase):
    def test_non_product_default_identity_and_supplementary_group_are_frozen(self):
        identity=builder.parse_portal_identity(output(),'fixtureportal')
        self.assertEqual((identity['uid'],identity['gid'],identity['groups']),(4242,4343,[4343,4444]))
        recipe=['RUN addgroup -S fixtureportal && adduser -S fixtureportal -G fixtureportal',
                'COPY --chown=fixtureportal runtime/ /','USER fixtureportal']
        result=builder.freeze_portal_dockerfile_identity(recipe,identity,'fixtureportal')
        self.assertIn('addgroup -S -g 4343 fixtureportal',result[0])
        self.assertIn('adduser -S -u 4242 fixtureportal -G fixtureportal',result[0])
        self.assertIn('addgroup fixtureportal fixtureshare',result[0])
        self.assertEqual(result[1],'COPY --chown=4242:4343 runtime/ /')
        self.assertEqual(result[-1],'USER fixtureportal')

    def test_numeric_user_and_explicit_group_preserve_the_runtime_reference(self):
        identity=builder.parse_portal_identity(output(gid=4444,groups='4444'),'4242:4444')
        self.assertEqual(identity['passwd_gid'],4343)
        recipe=['RUN addgroup -S 4242:4444 && adduser -S 4242:4444 -G 4242:4444','USER 4242:4444']
        result=builder.freeze_portal_dockerfile_identity(recipe,identity,'4242:4444')
        self.assertEqual(result[-1],'USER 4242:4444')
        self.assertIn('-u 4242 fixtureportal -G fixtureportal',result[0])

    def test_unknown_malformed_ambiguous_or_privileged_identity_fails_closed(self):
        cases=[('', 'fixtureportal'),(output(uid=0,user='root'),'root'),
               (output(gid=0,groups='0'),'fixtureportal'),
               (output().replace('uid=4242','uid=unknown'),'fixtureportal'),
               (output()+'passwd=alias:4242:4343\n','fixtureportal'),
               (output()+'group=alias:4343\n','fixtureportal'),
               (output().replace('groups=4343 4444','groups=4343 4343'),'fixtureportal'),
               (output().replace('group=fixtureshare:4444\n',''),'fixtureportal'),
               (output(),'missing'),(output(),'fixtureportal; touch /tmp/injected'),
               (output(),'4242:5555')]
        for raw,user in cases:
            with self.subTest(user=user,raw=raw[:30]),self.assertRaises((AssertionError,TypeError)):
                builder.parse_portal_identity(raw,user)
        with patch.object(builder,'run') as run,self.assertRaises(AssertionError):
            builder.probe_portal_identity('base',{'User':None},{})
        run.assert_not_called()

    def test_candidate_gate_rejects_changed_uid_gid_membership_or_user_reference(self):
        identity=builder.parse_portal_identity(output(),'fixtureportal')
        self.assertEqual(builder.verify_portal_numeric_identity(identity,copy.deepcopy(identity)),identity)
        for key,value in [('uid',4243),('gid',4444),('groups',[4343]),('configured_user','4242:4343')]:
            altered=copy.deepcopy(identity);altered[key]=value
            with self.subTest(field=key),self.assertRaises(AssertionError):
                builder.verify_portal_numeric_identity(identity,altered)
        with self.assertRaises(AssertionError):builder.freeze_portal_dockerfile_identity([],identity,'fixtureportal')

    def test_probe_uses_default_runtime_user_with_no_network_or_writable_filesystem(self):
        captured=[]
        def run(argv,**kwargs):captured.append((argv,kwargs));return output()
        with patch.object(builder,'run',side_effect=run):
            result=builder.probe_portal_identity('immutable-base',{'User':'fixtureportal'},{'DOCKER_HOST':'unix:///var/run/docker.sock'})
        args,kwargs=captured[0]
        self.assertEqual(result['uid'],4242)
        for value in ('--read-only','--network=none','--pull=never','--cap-drop=ALL','--security-opt=no-new-privileges'):
            self.assertIn(value,args)
        self.assertNotIn('--user',args)
        self.assertEqual(args[-1],builder.PORTAL_IDENTITY_PROBE)
        self.assertEqual(kwargs['env']['DOCKER_HOST'],'unix:///var/run/docker.sock')
        self.assertTrue(kwargs['capture_stdout'])

    def test_logged_probe_output_is_returned_without_stderr_contamination(self):
        with tempfile.TemporaryDirectory(prefix='codex-portal-identity-log-') as directory:
            log=Path(directory)/'identity.log'
            output=builder.run([sys.executable,'-c',"import sys; print('uid=4242'); print('probe diagnostic',file=sys.stderr)"],
                               log=log,capture_stdout=True)
            self.assertEqual(output,'uid=4242')
            self.assertIn('uid=4242',log.read_text());self.assertIn('probe diagnostic',log.read_text())
            self.assertEqual(builder.run([sys.executable,'-c',"print('streamed build output')"],log=log),'')
            self.assertIn('streamed build output',log.read_text())

    def test_failed_logged_probe_keeps_diagnostics_and_raises(self):
        with tempfile.TemporaryDirectory(prefix='codex-portal-identity-log-') as directory:
            log=Path(directory)/'identity.log'
            with self.assertRaises(subprocess.CalledProcessError):
                builder.run([sys.executable,'-c',"import sys; print('partial identity'); print('probe failed',file=sys.stderr); sys.exit(9)"],
                            log=log,capture_stdout=True)
            self.assertIn('partial identity',log.read_text());self.assertIn('probe failed',log.read_text())


@unittest.skipUnless(os.environ.get('PORTAL_NUMERIC_IDENTITY_DOCKER_TESTS')=='1','explicit isolated Docker fixture required')
class NumericIdentityDockerTests(unittest.TestCase):
    def test_existing_portal_base_identity_is_resolved_with_production_logging(self):
        image=os.environ.get('PORTAL_NUMERIC_IDENTITY_EXISTING_BASE')
        if not image:self.skipTest('explicit existing portal base required')
        env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock'}
        config=json.loads(subprocess.check_output(['docker','image','inspect',image],env=env,text=True))[0]['Config']
        expected=builder.probe_portal_identity(image,config,env)
        with tempfile.TemporaryDirectory(prefix='codex-portal-existing-log-') as directory:
            log=Path(directory)/'portal-base-identity.log'
            actual=builder.probe_portal_identity(image,config,env,log)
            self.assertEqual(actual,expected)
            self.assertIn('uid='+str(expected['uid']),log.read_text())
            self.assertIn('gid='+str(expected['gid']),log.read_text())
            self.assertIn('groups=',log.read_text())

    def test_real_non_1001_identity_groups_and_payload_owner_survive_fresh_runtime(self):
        runtime=builder.portal_runtime_base((ROOT/'enterprise-ai-portal/Dockerfile').read_text())
        subprocess.run(['docker','image','inspect',runtime],check=True,stdout=subprocess.DEVNULL)
        nonce=uuid.uuid4().hex[:12];base='codex-portal-numeric:'+nonce+'-base';candidate='codex-portal-numeric:'+nonce+'-candidate'
        env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_BUILDKIT':'0'}
        self.addCleanup(lambda:subprocess.run(['docker','image','rm','-f',base,candidate],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        with tempfile.TemporaryDirectory(prefix='codex-portal-numeric-') as directory:
            path=Path(directory);dockerfile=path/'Dockerfile'
            dockerfile.write_text('FROM '+runtime+'\nRUN addgroup -S -g 4343 fixtureportal && addgroup -S -g 4444 fixtureshare && adduser -S -u 4242 fixtureportal -G fixtureportal && addgroup fixtureportal fixtureshare\nUSER fixtureportal\n')
            subprocess.run(['docker','build','--pull=false','--network=none','--label','codex.task=portal-numeric-identity-fixture','-t',base,str(path)],env=env,check=True,stdout=subprocess.DEVNULL)
            config=json.loads(subprocess.check_output(['docker','image','inspect',base],env=env,text=True))[0]['Config']
            identity=builder.probe_portal_identity(base,config,env)
            self.assertEqual(identity['uid'],4242);self.assertEqual(identity['gid'],4343);self.assertEqual(identity['groups'],[4343,4444])
            (path/'runtime').mkdir();marker=path/'runtime/identity-marker';marker.write_text('ownership-proof');marker.chmod(0o640)
            recipe=['FROM '+runtime,'RUN addgroup -S fixtureportal && adduser -S fixtureportal -G fixtureportal','COPY --chown=fixtureportal runtime/ /','USER fixtureportal']
            dockerfile.write_text('\n'.join(builder.freeze_portal_dockerfile_identity(recipe,identity,'fixtureportal'))+'\n')
            subprocess.run(['docker','build','--pull=false','--network=none','--label','codex.task=portal-numeric-identity-fixture','-t',candidate,str(path)],env=env,check=True,stdout=subprocess.DEVNULL)
            config=json.loads(subprocess.check_output(['docker','image','inspect',candidate],env=env,text=True))[0]['Config']
            actual=builder.probe_portal_identity(candidate,config,env)
            builder.verify_portal_numeric_identity(identity,actual)
            result=subprocess.check_output(['docker','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--entrypoint','sh',candidate,'-ec','test "$(cat /identity-marker)" = ownership-proof; test -d /home/fixtureportal; stat -c "%u:%g" /identity-marker'],env=env,text=True)
            self.assertEqual(result.strip(),'4242:4343')

    def test_existing_pinned_node_account_is_verified_instead_of_reallocated(self):
        runtime=builder.portal_runtime_base((ROOT/'enterprise-ai-portal/Dockerfile').read_text())
        nonce=uuid.uuid4().hex[:12];base='codex-portal-numeric:'+nonce+'-node-base';candidate='codex-portal-numeric:'+nonce+'-node-candidate'
        env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_BUILDKIT':'0'}
        self.addCleanup(lambda:subprocess.run(['docker','image','rm','-f',base,candidate],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        with tempfile.TemporaryDirectory(prefix='codex-portal-node-') as directory:
            path=Path(directory);recipe=path/'Dockerfile';recipe.write_text('FROM '+runtime+'\nUSER node\n')
            subprocess.run(['docker','build','--pull=false','--network=none','--label','codex.task=portal-numeric-identity-fixture','-t',base,str(path)],env=env,check=True,stdout=subprocess.DEVNULL)
            config=json.loads(subprocess.check_output(['docker','image','inspect',base],env=env,text=True))[0]['Config']
            identity=builder.probe_portal_identity(base,config,env)
            self.assertEqual(identity['uid'],1000)
            lines=['FROM '+runtime,'RUN addgroup -S node && adduser -S node -G node','USER node']
            recipe.write_text('\n'.join(builder.freeze_portal_dockerfile_identity(lines,identity,'node'))+'\n')
            subprocess.run(['docker','build','--pull=false','--network=none','--label','codex.task=portal-numeric-identity-fixture','-t',candidate,str(path)],env=env,check=True,stdout=subprocess.DEVNULL)
            config=json.loads(subprocess.check_output(['docker','image','inspect',candidate],env=env,text=True))[0]['Config']
            builder.verify_portal_numeric_identity(identity,builder.probe_portal_identity(candidate,config,env))


if __name__=='__main__':unittest.main()

