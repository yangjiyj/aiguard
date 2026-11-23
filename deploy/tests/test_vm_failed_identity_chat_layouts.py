"""Exercise standard deploy/docker-compose layout with operator/artifact UID split."""
import ast, hashlib, json, os, shutil, stat, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_failed_identity_chat_input_owner as ownership
recovery=ownership.recovery

class RecoveryBootstrapLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.installed=self.root/'releases'/'original';self.installed.mkdir(parents=True)
        (self.root/'current').symlink_to(self.installed,target_is_directory=True)
        self.media=self.root/'development-releases'/'dev-fixture';(self.media/'state').mkdir(parents=True)
        self.calls=[];self.real_stat=Path.stat;self.real_lstat=Path.lstat
        directory=Path(os.environ.get('JJD_RECOVERY_LAYOUT_SOURCE_DIR',Path(__file__).resolve().parents[1]/'release'))
        source=(directory/'deploy_vm_development.py').read_text();tree=ast.parse(source)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='run_failed_recovery_helper')
        namespace={'Path':Path,'stat':stat,'json':json,'hashlib':hashlib,'os':os,
                   'require':lambda condition,message:None if condition else (_ for _ in ()).throw(RuntimeError(message)),
                   'protected':lambda path:Path(path),'run_installation_helper':lambda command,root,**kwargs:self.calls.append((command,kwargs))}
        exec(ast.get_source_segment(source,function),namespace);self.run=namespace['run_failed_recovery_helper']
        self.command=['python3','-I','-B','/root/pinned-recovery','--media',str(self.media)]
    def layout(self,relative):
        self.workdir=self.installed/relative
        (self.workdir/'bin').mkdir(parents=True,exist_ok=True)
        self.before={'live':str(self.workdir/'active-config'/'failed.json'),'compose_sha256':{}}
        for path,mode in ((self.workdir/'docker-compose.offline.yml',0o600),(self.workdir/'bin/docker-compose',0o700)):
            path.write_bytes(b'original artifact from UID1000');path.chmod(mode)
            self.before['compose_sha256'][str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        (self.media/'state/before.json').write_text(json.dumps(self.before))
    def fake_stat(self,path,*args,**kwargs):
        value=self.real_stat(path,*args,**kwargs)
        if path==self.installed:
            fields=list(value);fields[4]=0;fields[5]=0;return os.stat_result(fields)
        return value
    def fake_lstat(self,path):
        value=self.real_lstat(path);fields=list(value)
        fields[4]=1000 if path.name in ('docker-compose.offline.yml','docker-compose') else 0
        fields[5]=1000 if fields[4]==1000 else 0
        return os.stat_result(fields)
    def invoke(self):
        with patch.object(Path,'stat',lambda path,*a,**kw:self.fake_stat(path,*a,**kw)),\
             patch.object(Path,'lstat',lambda path:self.fake_lstat(path)),\
             patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='YY',pw_uid=1001,pw_gid=1001)) as account:
            self.run(self.command,self.root,recovery_operator_uid=1001)
            self.assertEqual(account.call_args_list,[unittest.mock.call(1001)])
        self.assertEqual(self.calls[0][0][-4:],['--recovery-operator-uid','1001','--recovery-operator-gid','1001'])
    def test_legacy_direct_release_layout_authenticates_operator_1001(self):
        self.layout('');self.invoke()
    def test_standard_nested_layout_uses_workdir_roles_and_ignores_release_root_decoys(self):
        self.layout('deploy/docker-compose')
        (self.installed/'bin').mkdir()
        (self.installed/'docker-compose.offline.yml').write_bytes(b'wrong root-level decoy')
        (self.installed/'bin/docker-compose').write_bytes(b'wrong root-level executable')
        self.invoke()
    def test_nested_artifact_digest_drift_fails_before_sudo_or_helper(self):
        self.layout('deploy/docker-compose');(self.workdir/'bin/docker-compose').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'digest'):self.invoke()
        self.assertEqual(self.calls,[])
    def test_nested_executable_mode_drift_fails_before_sudo_or_helper(self):
        self.layout('deploy/docker-compose');(self.workdir/'bin/docker-compose').chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'protection|mode'):self.invoke()
        self.assertEqual(self.calls,[])
    def test_other_nested_layout_is_not_silently_treated_as_the_install_root(self):
        self.layout('other')
        with self.assertRaisesRegex(RuntimeError,'installation'):self.invoke()
        self.assertEqual(self.calls,[])
    def test_standard_layout_symlink_escape_is_rejected(self):
        self.layout('deploy/docker-compose')
        foreign=self.root/'foreign';foreign.mkdir()
        shutil.rmtree(self.workdir);self.workdir.symlink_to(foreign,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'installation'):self.invoke()
        self.assertEqual(self.calls,[])

class NestedInstalledArtifactTests(ownership.InstalledInputOwnerTests):
    """Run all five artifact/FD/private-copy tests in the standard nested layout."""
    def setUp(self):
        super().setUp()
        nested=self.work/'deploy/docker-compose';(nested/'bin').mkdir(parents=True,mode=0o700)
        paths={self.config:nested/'docker-compose.offline.yml',self.binary:nested/'bin/docker-compose',self.other:nested/'unapproved.yml'}
        previous=self.before['compose_sha256'];index=json.loads((self.media/'state/compose-snapshots.json').read_text())
        for old,new in paths.items():old.rename(new)
        self.config,self.binary,self.other=paths[self.config],paths[self.binary],paths[self.other]
        self.work=nested
        self.before={'live':str(nested/'active-config'/'failed.json'),'compose_sha256':{str(new):previous[str(old)] for old,new in paths.items()}}
        (self.media/'state/compose-snapshots.json').write_text(json.dumps({str(new):index[str(old)] for old,new in paths.items()}))
        self.home=self.home/'standard-layout';self.home.mkdir()
        recovery.bind_installed_artifacts(self.media,self.home,self.before)

if __name__=='__main__':unittest.main()
