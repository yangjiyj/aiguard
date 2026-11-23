"""Mixed-owner inputs remain limited to two original stage-pinned files."""
import contextlib, contextvars, hashlib, inspect, json, os, stat, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_failed_identity_chat_recovery as legacy
recovery=legacy.recovery
vm=legacy.vm

class InstalledInputOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.work=self.root/'releases'/'original';(self.work/'bin').mkdir(parents=True,mode=0o700)
        self.config=self.work/'docker-compose.offline.yml';self.binary=self.work/'bin/docker-compose';self.other=self.work/'unapproved.yml'
        for path,mode in ((self.config,0o600),(self.binary,0o700),(self.other,0o600)):
            path.write_bytes(b'original pinned input');path.chmod(mode)
            if os.getuid()==0:os.chown(path,1000,1000)
        self.before={'live':str(self.work/'active-config'/'failed.json'),'compose_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.config,self.binary,self.other)}}
        self.media=self.root/'development-releases'/'dev-fixture';original=self.media/'state/original-compose';original.mkdir(parents=True)
        self.home=self.root/'development-releases'/'failed-apply-recoveries'/'fixture';self.home.mkdir(parents=True)
        index={str(self.config):'00-config',str(self.binary):'01-compose',str(self.other):'02-other'}
        (self.media/'state/compose-snapshots.json').write_text(json.dumps(index))
        for name in index.values():(original/name).write_bytes(b'original pinned input')
        @contextlib.contextmanager
        def parent(path):
            descriptor=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY)
            try:yield descriptor,Path(path).name,lambda:None
            finally:os.close(descriptor)
        self.addCleanup(patch.stopall)
        def write(path,value):path.write_text(json.dumps(value));path.chmod(0o600)
        source=SimpleNamespace(ROOT=self.root,INSTALL_OWNER=contextvars.ContextVar('owner',default=None),safe_parent=parent,
                               fd_identity=vm.fd_identity,written_identity=vm.written_identity,write_json=write,verify_file_fd=vm.verify_file_fd,verify_directory_fd=lambda *args:None)
        patch.object(recovery,'vm',source).start()
        patch.object(recovery.os,'geteuid',return_value=0).start()
        actual_fstat=os.fstat;actual_stat=os.stat
        def root_directory(info):
            if stat.S_ISDIR(info.st_mode) and os.geteuid()==0:
                values=list(info);values[4]=0;values[5]=0;return os.stat_result(values)
            return info
        patch.object(os,'fstat',side_effect=lambda fd:root_directory(actual_fstat(fd))).start()
        patch.object(os,'stat',side_effect=lambda *args,**kwargs:root_directory(actual_stat(*args,**kwargs))).start()
        patch.object(recovery,'RECOVERY_OPERATOR',(1001,1001,'YY')).start()
        patch.object(recovery,'INSTALLED_INPUT_ARTIFACTS',{}).start()
        # Root snapshot ownership/path guards are independently exercised by the
        # existing failed-recovery fixture; these bytes model that authenticated read.
        patch.object(recovery,'pinned',side_effect=lambda path,expected=None:Path(path).read_bytes()).start()
        recovery.bind_installed_artifacts(self.media,self.home,self.before)
    def test_operator_and_artifact_creator_are_distinct_and_only_two_roles_are_allowed(self):
        self.assertEqual(recovery.RECOVERY_OPERATOR,(1001,1001,'YY'))
        self.assertNotEqual(recovery.INSTALLED_INPUT_ARTIFACTS[str(self.binary)]['metadata']['uid'],1001)
        self.assertEqual(recovery.installed_read(self.config,input_binding=self.before),b'original pinned input')
        self.assertEqual(recovery.installed_read(self.binary,input_binding=self.before),b'original pinned input')
        with self.assertRaises(RuntimeError):recovery.installed_read(self.other,input_binding=self.before)
        with self.assertRaises(RuntimeError):recovery.installed_read(self.config)
    def test_changed_metadata_mode_hardlink_digest_or_snapshot_is_rejected(self):
        for mode in (0o644,0o660,0o777):
            self.config.chmod(mode)
            with self.subTest(mode=mode),self.assertRaises(RuntimeError):recovery.installed_read(self.config,input_binding=self.before)
        self.config.chmod(0o600);self.config.write_bytes(b'changed')
        with self.assertRaises(RuntimeError):recovery.installed_read(self.config,input_binding=self.before)
        self.config.write_bytes(b'original pinned input');os.link(self.config,self.work/'alias')
        with self.assertRaises(RuntimeError):recovery.installed_read(self.config,input_binding=self.before)
    def test_root_snapshot_copy_is_private_and_original_artifact_is_not_executed_or_changed(self):
        original=self.binary.stat()
        with patch.object(recovery.os,'geteuid',return_value=os.getuid()):
            executable=recovery.root_owned_compose(self.home,self.binary,self.before)
        self.assertNotEqual(executable,self.binary)
        self.assertEqual(executable.read_bytes(),b'original pinned input')
        self.assertEqual(executable.stat().st_mode&0o777,0o700)
        self.assertEqual(executable.stat().st_uid,os.getuid())
        self.assertEqual(recovery.installed_artifact_metadata(self.binary.stat()),recovery.installed_artifact_metadata(original))
    def test_artifact_attestation_cannot_silently_change_during_recovery(self):
        self.binary.write_bytes(b'changed source')
        with self.assertRaises(RuntimeError):recovery.bind_installed_artifacts(self.media,self.home,self.before)
    def test_operator_authentication_uses_real_sudo_identity_without_global_installation_owner(self):
        account=SimpleNamespace(pw_name='YY',pw_gid=1001)
        with patch.object(recovery.pwd,'getpwuid',return_value=account),patch.dict(os.environ,{'SUDO_UID':'1001','SUDO_GID':'1001','SUDO_USER':'YY'}):
            recovery.configure_recovery_operator(1001,1001)
            self.assertEqual(recovery.RECOVERY_OPERATOR,(1001,1001,'YY'))
            self.assertIsNone(recovery.vm.INSTALL_OWNER.get())
        with patch.dict(os.environ,{},clear=True),self.assertRaises(RuntimeError):recovery.configure_recovery_operator(1001,1001)

class RecoveryOwnerBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.installed=self.root/'releases'/'original';(self.installed/'bin').mkdir(parents=True)
        (self.root/'current').symlink_to(self.installed,target_is_directory=True)
        self.media=self.root/'development-releases'/'dev-fixture';(self.media/'state').mkdir(parents=True)
        self.before={'live':str(self.installed/'active-config'/'failed.json'),'compose_sha256':{}}
        for path,mode in ((self.installed/'docker-compose.offline.yml',0o600),(self.installed/'bin/docker-compose',0o700)):
            path.write_bytes(b'pinned');path.chmod(mode);self.before['compose_sha256'][str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        (self.media/'state/before.json').write_text(json.dumps(self.before))
        self.calls=[]
        namespace={'Path':Path,'stat':stat,'json':json,'hashlib':hashlib,'os':os,
                   'require':lambda condition,message:None if condition else (_ for _ in ()).throw(RuntimeError(message)),
                   'protected':lambda path:Path(path),'run_installation_helper':lambda command,root,**kwargs:self.calls.append((command,kwargs))}
        exec(inspect.getsource(legacy.fixture.deploy.run_failed_recovery_helper),namespace)
        self.run=namespace['run_failed_recovery_helper'];self.command=['python3','-I','-B','/private/pinned-helper','--media',str(self.media)]
    def root_owned_directory(self,path,*args,**kwargs):
        actual=self.real_stat(path,*args,**kwargs)
        if path==self.installed:
            values=list(actual);values[4]=0;values[5]=0;return os.stat_result(values)
        return actual
    def mocked_lstat(self,path):
        actual=self.real_lstat(path);values=list(actual)
        values[4]=1000 if path.name in ('docker-compose.offline.yml','docker-compose') else 0
        values[5]=1000 if values[4]==1000 else 0
        return os.stat_result(values)
    def test_default_uses_real_double_sudo_and_never_supplies_sudo_environment(self):
        self.real_lstat=Path.lstat;self.real_stat=Path.stat
        with patch.object(Path,'stat',lambda path,*a,**kw:self.root_owned_directory(path,*a,**kw)),patch.object(Path,'lstat',lambda path:self.mocked_lstat(path)),patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='YY',pw_uid=1001,pw_gid=1001)):
            self.run(self.command,self.root,recovery_operator_uid=1001)
        command,kwargs=self.calls[0]
        self.assertEqual(command[:9],['/usr/bin/sudo','-u','YY','-n','--','/usr/bin/sudo','-n','--','python3'])
        self.assertEqual(command[-4:],['--recovery-operator-uid','1001','--recovery-operator-gid','1001'])
        self.assertNotIn('SUDO_UID=',repr(command));self.assertIsNone(kwargs['stdin'])
    def test_customer_password_is_only_forwarded_as_anonymous_stdin_fd(self):
        self.real_lstat=Path.lstat;self.real_stat=Path.stat;read,write=os.pipe()
        try:
            # Unit test uses fd 0 just as the root SSH launcher; no password is stored.
            real_fstat=os.fstat
            def info(fd):return real_fstat(read if fd==0 else fd)
            with patch.object(Path,'stat',lambda path,*a,**kw:self.root_owned_directory(path,*a,**kw)),patch.object(Path,'lstat',lambda path:self.mocked_lstat(path)),patch('pwd.getpwuid',return_value=SimpleNamespace(pw_name='YY',pw_uid=1001,pw_gid=1001)),patch.object(os,'fstat',side_effect=info):
                self.run(self.command,self.root,installed_input_password_fd=0,recovery_operator_uid=1001)
        finally:os.close(read);os.close(write)
        command,kwargs=self.calls[0]
        self.assertEqual(command[:11],['/usr/bin/sudo','-u','YY','-n','--','/usr/bin/sudo','-S','-p','','--','python3'])
        self.assertEqual(kwargs,{'stdin':0});self.assertNotIn('123',repr(command))
    def test_non_pipe_customer_stdin_is_rejected(self):
        with patch.object(os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600)),self.assertRaisesRegex(RuntimeError,'pipe'):
            self.run(self.command,self.root,installed_input_password_fd=0,recovery_operator_uid=1001)

if __name__=='__main__':unittest.main()
