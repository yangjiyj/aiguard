#!/usr/bin/env python3
"""Run the real CLI functions against separate current/rollback directories."""
import json, os, pathlib, shutil, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]

class RollbackComposeAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.current = self.root/'current'
        self.previous = self.root/'backup/legacy-release'
        self.log = self.root/'wrapper.json'
        raw = (ROOT/'deploy/offline-installer/jjdctl').read_text()
        self.assertEqual(raw.count('main "$@"'), 1)
        for name, release in [('current', self.current), ('previous', self.previous)]:
            dc = release/'deploy/docker-compose'
            dc.mkdir(parents=True)
            (dc/'.env').write_text('export JJD_TEST_RELEASE_NAME='+name+'\n')
            (dc/'docker-compose.offline.yml').write_text('services: {}\n')
            wrapper = dc/'compose-wrapper.sh'
            wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -c '+"'import json,os,sys;open(os.environ[\"JJD_TEST_WRAPPER_LOG\"],\"w\").write(json.dumps({\"cwd\":os.getcwd(),\"argv\":sys.argv[1:],\"release_env\":os.environ.get(\"JJD_TEST_RELEASE_NAME\")}))'"+' "$@"\n')
        # jjdctl reads .env through the shared safe loader that ships next to it (deploy/lib).
        (self.current/'deploy/lib').mkdir(parents=True)
        shutil.copyfile(ROOT/'deploy/lib/jjd-env.sh', self.current/'deploy/lib/jjd-env.sh')
        self.source = self.current/'jjdctl'
        self.source.write_text(raw.replace('main "$@"',''))
        # Historical helpers do not implement forced recreation. The current
        # trusted compose resolver must handle the rollback target itself.
        (self.previous/'jjdctl').write_text('#!/bin/sh\nexit 0\n')
        (self.previous/'jjdctl').chmod(0o755)
    def run_cli(self, script):
        return subprocess.run(['bash','-Eeuo','pipefail','-c','source "$1"; '+script,'fixture',str(self.source),str(self.previous)], env=dict(os.environ,JJD_TEST_WRAPPER_LOG=str(self.log)),capture_output=True,timeout=10)
    def test_rollback_recreates_unchanged_services_from_previous_authority(self):
        result = self.run_cli('start_rollback_release "$2"')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertTrue(self.log.is_file(),'rollback delegated to a historical helper without enforcing fresh Compose ownership')
        value=json.loads(self.log.read_bytes())
        self.assertEqual(value['cwd'],str(self.previous/'deploy/docker-compose'))
        self.assertEqual(value['release_env'],'previous')
        self.assertEqual(value['argv'],['-f',str(self.previous/'deploy/docker-compose/docker-compose.offline.yml'),'up','-d','--remove-orphans','--force-recreate'])
    def test_rollback_requires_previous_environment(self):
        (self.previous/'deploy/docker-compose/.env').unlink()
        result=self.run_cli('start_rollback_release "$2"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.log.exists())
    def test_rollback_rejects_untrusted_active_chain(self):
        state=self.previous/'deploy/docker-compose/.upgrade'
        state.mkdir()
        chain=state/'compose-files';chain.write_text('/tmp/outside-rollback.yml\n');chain.chmod(0o600)
        result=self.run_cli('start_rollback_release "$2"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.log.exists())
    def test_rollback_does_not_replace_callers_source_variables(self):
        result=self.run_cli('before="$ROOT|$DC|$ENV|$COMPOSE"; start_rollback_release "$2"; [[ "$before" == "$ROOT|$DC|$ENV|$COMPOSE" ]]')
        self.assertEqual(result.returncode,0,result.stderr.decode())
    def test_normal_start_does_not_force_recreation(self):
        result=self.run_cli('need_root() { :; }; main start')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        value=json.loads(self.log.read_bytes())
        self.assertEqual(value['cwd'],str(self.current/'deploy/docker-compose'))
        self.assertNotIn('--force-recreate',value['argv'])

    # ---- 软链布局：/opt/jjdguard/current -> releases/<版本> ----
    # 非 root 跑测试：桩掉 root 属主/0600 校验，路径语义校验保持真实。
    STUBS = ('need_root() { :; }; require_root_state_file() { [[ -f "$1" && ! -L "$1" ]]; }; '
             'stat() { if [[ "$1" == -Lc ]]; then case "$2" in %u) echo 0;; %a) echo 600;; esac; else command stat "$@"; fi; }; ')
    def chain_setup(self, release, entries, project_directory=None):
        dc = release/'deploy/docker-compose'
        (dc/'active-config').mkdir(exist_ok=True)
        state = dc/'.upgrade'; state.mkdir(exist_ok=True)
        (state/'compose-files').write_text(''.join(e+'\n' for e in entries))
        if project_directory is not None:
            (state/'project-name').write_text('jjdtest\n')
            (state/'project-directory').write_text(project_directory+'\n')
        return dc
    def real_layer(self, release, name='dev.yml'):
        f = release/'deploy/docker-compose/active-config'/name
        f.parent.mkdir(parents=True, exist_ok=True); f.write_text('services: {}\n'); f.chmod(0o600)
        return f
    def link_release(self, release, name):
        """base/name -> release，返回软链形式的 release 路径。"""
        link = self.root/name
        link.symlink_to(release)
        return link
    def run_stubbed(self, script):
        return self.run_cli(self.STUBS + script)

    def test_rollback_accepts_symlinked_previous_release(self):
        f = self.real_layer(self.previous)
        self.chain_setup(self.previous, [str(f)])
        link = self.link_release(self.previous, 'prev-link')
        result = self.run_stubbed('start_rollback_release "$3"'.replace('$3', str(link)))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = json.loads(self.log.read_bytes())
        self.assertIn(str(f), value['argv'])
        self.assertEqual(value['release_env'], 'previous')
    def test_compose_accepts_symlink_form_chain_entries(self):
        real = self.real_layer(self.current)
        link = self.link_release(self.current, 'cur-link')
        self.chain_setup(self.current, [str(link/'deploy/docker-compose/active-config/dev.yml')])
        result = self.run_stubbed('main start')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(str(real), json.loads(self.log.read_bytes())['argv'])
    def test_compose_rejects_entry_that_is_symlink_escaping(self):
        outside = self.root/'outside.yml'; outside.write_text('x'); outside.chmod(0o600)
        self.real_layer(self.current)
        evil = self.current/'deploy/docker-compose/active-config/evil.yml'; evil.symlink_to(outside)
        self.chain_setup(self.current, [str(evil)])
        result = self.run_stubbed('main start')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(self.log.exists())
    def test_compose_rejects_parent_directory_symlink_escape(self):
        out = self.root/'outside-dir'; out.mkdir(); (out/'evil.yml').write_text('x'); (out/'evil.yml').chmod(0o600)
        self.real_layer(self.current)
        (self.current/'deploy/docker-compose/active-config/sub').symlink_to(out)
        self.chain_setup(self.current, [str(self.current/'deploy/docker-compose/active-config/sub/evil.yml')])
        result = self.run_stubbed('main start')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(self.log.exists())
    def test_compose_rejects_active_config_symlink_escape(self):
        out = self.root/'outside-active'; out.mkdir(); (out/'dev.yml').write_text('x'); (out/'dev.yml').chmod(0o600)
        dc = self.current/'deploy/docker-compose'
        (dc/'.upgrade').mkdir(); (dc/'active-config').symlink_to(out)
        (dc/'.upgrade/compose-files').write_text(str(dc/'active-config/dev.yml')+'\n')
        result = self.run_stubbed('main start')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(self.log.exists())
    def test_project_directory_symlink_to_real_dc_is_accepted(self):
        f = self.real_layer(self.current)
        link = self.link_release(self.current, 'cur-link')
        self.chain_setup(self.current, [str(f)], str(link/'deploy/docker-compose'))
        result = self.run_stubbed('main start')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        argv = json.loads(self.log.read_bytes())['argv']
        self.assertEqual(argv[argv.index('--project-directory')+1], str(self.current/'deploy/docker-compose'))
    def test_project_directory_symlink_escape_is_rejected(self):
        f = self.real_layer(self.current)
        other = self.root/'elsewhere'; other.mkdir()
        link = self.root/'pd-link'; link.symlink_to(other)
        self.chain_setup(self.current, [str(f)], str(link))
        result = self.run_stubbed('main start')
        self.assertNotEqual(result.returncode, 0); self.assertFalse(self.log.exists())

if __name__=='__main__':unittest.main(verbosity=2)
