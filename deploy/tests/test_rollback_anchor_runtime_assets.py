#!/usr/bin/env python3
"""Exercise the real rollback anchor constructor without Docker or a VM."""
import os, pathlib, re, shutil, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]

class RollbackAnchorAssets(unittest.TestCase):
    def construct(self, directory, unsafe_agent=False):
        new = directory / 'new/deploy/docker-compose'
        old = directory / 'old/deploy/docker-compose'
        backup = directory / 'backups/20261017T000000Z'
        snapshot = directory / 'snapshots'
        for path in [new, old, backup, snapshot, new.parent/'offline-installer', new.parent/'lib', old.parent/'migrations']:
            path.mkdir(parents=True, exist_ok=True)
        for rel in ['deploy/offline-installer/jjdctl', 'deploy/offline-installer/wait-docker.sh', 'deploy/lib/captcha-login.sh', 'deploy/lib/jjd-env.sh', 'deploy/docker-compose/compose-wrapper.sh', 'deploy/docker-compose/smoke-test.sh', 'deploy/docker-compose/backup-db.sh', 'deploy/docker-compose/diagnose.sh']:
            shutil.copyfile(ROOT/rel, directory/'new'/rel)
        base = old/'docker-compose.offline.yml'
        shutil.copyfile(ROOT/'deploy/docker-compose/docker-compose.offline.yml', base)
        (old/'.env').write_text('COMPOSE_PROJECT_NAME=fixture\nJJD_VERSION=2.9.4\n')
        shutil.copyfile(base, snapshot/'base.yml')
        shutil.copyfile(old/'.env', snapshot/'old.env')
        (old.parent/'migrations/001_fixture.sql').write_text('SELECT 1;\n')
        if unsafe_agent:
            target = directory/'outside-agent'
            target.mkdir()
            (old/'agent-kit').symlink_to(target, target_is_directory=True)
        else:
            (old/'agent-kit').mkdir()
            (old/'agent-kit/client.zip').write_bytes(b'copy-boundary-fixture')
        (backup/'rollback-compose.yml').write_text('services:\n  proxy-server:\n    image: example.invalid/old:fixture\n')
        source = ROOT/'deploy/docker-compose/upgrade-bundle.sh'
        body = re.search(r'^create_legacy_release_anchor\(\) \{\n.*?^\}\n', source.read_text(), re.M|re.S)
        self.assertIsNotNone(body)
        functions = directory/'constructor.sh'
        functions.write_text(body[0])
        env = dict(os.environ, SCRIPT_DIR=str(new), BACKUP_DIR=str(backup), EXISTING_CONFIG_FILES=str(base), OLD_CONFIG_SNAPSHOT_FILES=str(snapshot/'base.yml'), EXISTING_WORK_DIR=str(old), OLD_ENV_SNAPSHOT_FILE=str(snapshot/'old.env'), EXISTING_PROJECT_NAME='fixture', UPGRADE_RUN_TIMESTAMP='20261017T000000Z')
        script = 'source "$1"; fail() { echo failed >&2; return 1; }; validate_config_snapshots() { return 0; }; create_legacy_release_anchor'
        result = subprocess.run(['bash','-Eeuo','pipefail','-c',script,'fixture',str(functions)], env=env, capture_output=True)
        return result, backup/'legacy-release'

    def test_actual_systemd_executables_are_available_after_current_switch(self):
        with tempfile.TemporaryDirectory() as temp:
            result, anchor = self.construct(pathlib.Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            unit = (ROOT/'deploy/offline-installer/jjdguard.service').read_text()
            commands = re.findall(r'^Exec(?:StartPre|Start|Stop)=(/opt/jjdguard/current/[^\s]+)', unit, re.M)
            self.assertEqual(len(commands), 3)
            for command in commands:
                target = anchor/command.removeprefix('/opt/jjdguard/current/')
                self.assertTrue(target.is_file() and os.access(target,os.X_OK), command+' missing from rollback anchor')
            self.assertEqual((anchor/'deploy/offline-installer/wait-docker.sh').read_bytes(), (ROOT/'deploy/offline-installer/wait-docker.sh').read_bytes())
            self.assertEqual((anchor/'deploy/lib/jjd-env.sh').read_bytes(), (ROOT/'deploy/lib/jjd-env.sh').read_bytes(), 'rollback anchor must carry the safe .env loader used by jjdctl and the ops scripts')

    def test_relative_compose_bind_assets_are_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            result, anchor = self.construct(pathlib.Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((anchor/'deploy/migrations/001_fixture.sql').is_file(), 'migration bind source missing')
            self.assertEqual((anchor/'deploy/migrations/001_fixture.sql').read_bytes(), b'SELECT 1;\n')

    def test_agent_download_bind_assets_are_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            result, anchor = self.construct(pathlib.Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue((anchor/'deploy/docker-compose/agent-kit/client.zip').is_file(), 'agent download bind source missing')
            self.assertEqual((anchor/'deploy/docker-compose/agent-kit/client.zip').read_bytes(), b'copy-boundary-fixture')

    def test_newly_retained_agent_assets_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            result, _ = self.construct(pathlib.Path(temp), unsafe_agent=True)
            self.assertNotEqual(result.returncode,0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
