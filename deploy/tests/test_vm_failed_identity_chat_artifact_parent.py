"""Only the stage-authenticated Compose artifact may use a creator-owned bin."""
import contextvars, hashlib, json, os, stat, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_vm_failed_identity_chat_recovery as legacy
recovery=legacy.recovery
real_vm=legacy.vm

class CreatorOwnedBinParentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.work=self.root/'releases'/'original'/'deploy/docker-compose';self.bin=self.work/'bin'
        self.bin.mkdir(parents=True,mode=0o700);self.binary=self.bin/'docker-compose';self.binary.write_bytes(b'pinned original binary');self.binary.chmod(0o700)
        self.media=self.root/'development-releases'/'dev-fixture';snapshots=self.media/'state/original-compose';snapshots.mkdir(parents=True)
        (snapshots/'original-compose').write_bytes(self.binary.read_bytes())
        (self.media/'state/compose-snapshots.json').write_text(json.dumps({str(self.binary):'original-compose'}))
        self.home=self.root/'development-releases'/'failed-apply-recoveries'/'creator-bin';self.home.mkdir(parents=True,mode=0o700)
        self.checksum=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.before={'live':str(self.work/'active-config'/'failed.json'),'compose_sha256':{str(self.binary):self.checksum}}
        for directory in self.root.rglob('*'):
            if directory.is_dir():directory.chmod(0o700)
        self.creator_uid=1000;self.file_uid=1000;self.extra_creator=set()
        self.actual_fstat=os.fstat;self.actual_stat=os.stat
        def metadata(info,path):
            values=list(info)
            uid=self.creator_uid if stat.S_ISDIR(info.st_mode) and (path==self.bin or path in self.extra_creator) else self.file_uid if path==self.binary else 0
            values[4]=uid;values[5]=uid;return os.stat_result(values)
        def fstat(fd):return metadata(self.actual_fstat(fd),Path(os.readlink('/proc/self/fd/'+str(fd))))
        def status(path,*args,**kwargs):
            full=Path(os.readlink('/proc/self/fd/'+str(kwargs['dir_fd'])))/path if kwargs.get('dir_fd') is not None else Path(path)
            return metadata(self.actual_stat(path,*args,**kwargs),full)
        self.addCleanup(patch.stopall)
        source=SimpleNamespace(ROOT=self.root,INSTALL_OWNER=contextvars.ContextVar('installation-owner',default=None),
          safe_parent=real_vm.safe_parent,verify_directory_fd=real_vm.verify_directory_fd,fd_identity=real_vm.fd_identity,
          written_identity=real_vm.written_identity,write_json=lambda path,value:path.write_text(json.dumps(value)))
        patch.object(recovery,'vm',source).start();patch.object(recovery.os,'geteuid',return_value=0).start()
        patch.object(recovery,'RECOVERY_OPERATOR',(1001,1001,'YY')).start();patch.object(recovery,'INSTALLED_INPUT_ARTIFACTS',{}).start()
        patch.object(recovery,'pinned',side_effect=lambda path,expected=None:Path(path).read_bytes()).start()
        patch.object(os,'fstat',side_effect=fstat).start();patch.object(os,'stat',side_effect=status).start()
    def test_original_safe_parent_rejects_but_exact_authenticated_role_is_accepted(self):
        with self.assertRaisesRegex(RuntimeError,'owner'):
            with real_vm.safe_parent(self.binary):pass
        recovery.bind_installed_artifacts(self.media,self.home,self.before)
        self.assertEqual(recovery.installed_read(self.binary,input_binding=self.before),b'pinned original binary')
        parent=recovery.INSTALLED_INPUT_ARTIFACTS[str(self.binary)]['parent']
        self.assertEqual((parent['uid'],parent['gid'],parent['mode']),(1000,1000,0o700))
        self.assertEqual(recovery.RECOVERY_OPERATOR,(1001,1001,'YY'));self.assertIsNone(recovery.vm.INSTALL_OWNER.get())
    def test_creator_bin_must_be_exactly_private_700(self):
        for mode in (0o755,0o770,0o777):
            self.bin.chmod(mode)
            with self.subTest(mode=mode),self.assertRaisesRegex(RuntimeError,'bin directory'):
                recovery.bind_installed_artifacts(self.media,self.home,self.before)
    def test_bin_creator_must_match_the_verified_binary_creator(self):
        self.creator_uid=2000
        with self.assertRaisesRegex(RuntimeError,'parent identity'):
            recovery.bind_installed_artifacts(self.media,self.home,self.before)
    def test_parent_metadata_is_rechecked_on_installed_reads(self):
        recovery.bind_installed_artifacts(self.media,self.home,self.before);self.creator_uid=2000
        with self.assertRaisesRegex(RuntimeError,'bin directory'):
            recovery.installed_read(self.binary,input_binding=self.before)
    def test_unrelated_creator_owned_parent_does_not_receive_an_exception(self):
        foreign=self.work/'other';foreign.mkdir(mode=0o700);self.extra_creator.add(foreign);path=foreign/'data';path.write_text('unapproved')
        with self.assertRaisesRegex(RuntimeError,'owner'):
            recovery.installed_read(path,input_binding=self.before)
    def test_root_owned_binary_in_creator_parent_remains_fail_closed(self):
        self.file_uid=0
        recovery.bind_installed_artifacts(self.media,self.home,self.before)
        self.assertEqual(recovery.INSTALLED_INPUT_ARTIFACTS,{})
        with self.assertRaisesRegex(RuntimeError,'owner'):
            recovery.installed_read(self.binary,input_binding=self.before)

if __name__=='__main__':unittest.main()
