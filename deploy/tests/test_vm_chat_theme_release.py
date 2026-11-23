import copy
import importlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.environ.get('JJD_CHAT_THEME_TEST_RELEASE_ROOT', str(Path(__file__).resolve().parents[1] / 'release')))
import build_vm_development as build
import vm_development_apply as vm


def theme_module():
    return importlib.import_module('vm_chat_theme_release')


class ChatThemeScopeTests(unittest.TestCase):
    def args(self, **changes):
        values = dict(chat_theme_only=True, console_only=False, security_engine_only=False,
                      engineering_only=False, portal_only=False, preserve_tier1=False,
                      migration=[], enable_file_detection=False)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_theme_build_carries_no_images(self):
        self.assertEqual(build.release_services(self.args()), ())

    def test_theme_cannot_be_combined_with_image_or_database_changes(self):
        for change in ({'console_only': True}, {'portal_only': True}, {'migration': ['bad.sql']},
                       {'enable_file_detection': True}, {'security_input_capacity': 9}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                build.release_services(self.args(**change))

    def manifest(self):
        theme = theme_module()
        return dict(schema=1, purpose='chat-theme-only', chat_theme_only=True,
                    release_id='dev-test', revision='a'*40, tree='b'*40,
                    services={}, migrations={}, theme_files={name: 'c'*64 for name in theme.THEME_FILES},
                    source_archive_sha256='d'*64, theme_archive_sha256='e'*64,
                    apply_script_sha256='f'*64, theme_script_sha256='1'*64)

    def test_vm_scope_targets_only_idp(self):
        target, preserved = vm.release_service_sets(self.manifest())
        self.assertEqual(target, ('chat-idp',))
        self.assertEqual(preserved, vm.SERVICES)

    def test_scope_rejects_missing_messages_and_unexpected_code(self):
        theme = theme_module()
        manifest = self.manifest()
        theme.validate_manifest(manifest)
        for change in ({'services': {'web-console': {}}}, {'migrations': {'bad.sql': 'c'*64}},
                       {'portal_only': True}, {'theme_files': {'../../bad': 'c'*64}},
                       {'theme_files': {name: value for name, value in manifest['theme_files'].items()
                                        if not name.endswith('messages_en.properties')}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                theme.validate_manifest(dict(manifest, **change))

    def row(self, root):
        return dict(Id='1'*64, Image='sha256:'+'2'*64,
                    Config={'Labels': {'com.docker.compose.service': 'chat-idp',
                                        'com.docker.compose.project.working_dir': str(root/'deploy/docker-compose')},
                            'User': '1000'}, State={'Status': 'running', 'StartedAt': 'before'},
                    RestartCount=0,
                    Mounts=[{'Destination': '/opt/keycloak/themes/jjdguard', 'Type': 'bind',
                             'Source': str(root/'deploy/docker-compose/chat/keycloak-themes/jjdguard'), 'RW': False}])

    def test_runtime_mount_must_match_authenticated_installation(self):
        theme = theme_module()
        root = Path('/opt/jjdguard/releases/test')
        good = self.row(root)
        self.assertEqual(theme.validate_idp_mount(good, root),
                         root/'deploy/docker-compose/chat/keycloak-themes/jjdguard')
        for mutate in (lambda row: row['Mounts'][0].update(RW=True),
                       lambda row: row['Mounts'][0].update(Source='/tmp/other'),
                       lambda row: row['Mounts'][0].update(Type='volume'),
                       lambda row: row['Config']['Labels'].update({'com.docker.compose.project.working_dir': '/tmp'})):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.assertRaises(RuntimeError):
                theme.validate_idp_mount(bad, root)

    def test_theme_archive_refuses_traversal_links_and_extra_files(self):
        theme = theme_module()
        for name, kind in (('../escape', tarfile.REGTYPE),
                           ('login/theme.properties', tarfile.SYMTYPE),
                           ('login/unreviewed.ftl', tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'theme.tar'
                with tarfile.open(path, 'w') as archive:
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    if kind == tarfile.REGTYPE:
                        info.size = 4
                        archive.addfile(info, io.BytesIO(b'evil'))
                    else:
                        info.linkname = '/tmp/outside'
                        archive.addfile(info)
                with self.assertRaises(RuntimeError):
                    theme.read_theme_archive(path.read_bytes(), self.manifest()['theme_files'])

    @staticmethod
    def versioned_assets():
        return {
            'login/theme.properties': b'parent=keycloak.v2\nstyles=css/styles.css css/jjdguard-portal-20261005.css?v=portal-20261005\n',
            'login/resources/css/jjdguard-portal-20261005.css': b'.kc-logo-text { background: url("../img/jjdguard-logo-portal-20261005.svg?v=portal-20261005"); }\n',
            'login/resources/img/jjdguard-logo-portal-20261005.svg': b'<svg></svg>\n',
            'login/messages/messages_en.properties': b'loginTitle=Enterprise AI Portal\n',
            'login/messages/messages_zh_CN.properties': b'loginTitle=Fixture\n',
        }

    @staticmethod
    def archive(assets):
        import hashlib
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, value in sorted(assets.items()):
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        return stream.getvalue(), {name: hashlib.sha256(value).hexdigest() for name, value in assets.items()}

    def test_theme_scope_requires_physical_versioned_resources_not_query_only(self):
        theme = theme_module()
        assets = self.versioned_assets()
        self.assertEqual(set(theme.THEME_FILES), set(assets))
        manifest = self.manifest()
        manifest['theme_files'] = {name: 'c'*64 for name in assets}
        theme.validate_manifest(manifest)
        old_paths = {name.replace('-portal-20261005', ''): value for name, value in manifest['theme_files'].items()}
        with self.assertRaises(RuntimeError):
            theme.validate_manifest(dict(manifest, theme_files=old_paths))

    def test_theme_archive_accepts_exact_frozen_versioned_resource_references(self):
        theme = theme_module()
        assets = self.versioned_assets()
        content, expected = self.archive(assets)
        self.assertEqual(theme.read_theme_archive(content, expected), assets)

    def test_theme_archive_rejects_stale_unlisted_or_unversioned_resource_references(self):
        theme = theme_module()
        for path, old, new in (
            ('login/theme.properties', b'jjdguard-portal-20261005.css', b'jjdguard.css'),
            ('login/theme.properties', b'?v=portal-20261005', b'?v=old'),
            ('login/theme.properties', b'css/styles.css ', b'css/unreviewed.css css/styles.css '),
            ('login/theme.properties', b'styles=', b'styles=css/styles.css\nstyles='),
            ('login/resources/css/jjdguard-portal-20261005.css', b'jjdguard-logo-portal-20261005.svg', b'jjdguard-logo.svg'),
            ('login/resources/css/jjdguard-portal-20261005.css', b'?v=portal-20261005', b'?v=old'),
            ('login/resources/css/jjdguard-portal-20261005.css', b'../img/', b'https://other.example/'),
        ):
            with self.subTest(path=path, new=new):
                assets = self.versioned_assets()
                assets[path] = assets[path].replace(old, new)
                content, expected = self.archive(assets)
                with self.assertRaises(RuntimeError):
                    theme.read_theme_archive(content, expected)

    def test_theme_build_freezes_only_exact_versioned_login_assets(self):
        theme = theme_module()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source'
            assets = self.versioned_assets()
            for name, content in assets.items():
                path = source/theme.THEME_PATH/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            helpers = source/'deploy/release'
            helpers.mkdir(parents=True)
            for name in ('vm_development_apply.py', 'vm_chat_theme_release.py'):
                (helpers/name).write_bytes(b'frozen fixture helper')
            media = Path(directory)/'media'
            manifest = self.manifest()
            theme.build_theme_media(source, media, manifest)
            self.assertEqual(set(manifest['theme_files']), set(assets))
            self.assertEqual(theme.read_theme_archive((media/'theme.tar').read_bytes(), manifest['theme_files']), assets)
            self.assertEqual(set(path.name for path in media.iterdir()), set(theme.MEDIA_FILES))

    def test_idp_readiness_honors_sso_relative_path_and_http_port(self):
        theme = theme_module()
        row = {'Config': {'Env': ['KC_HTTP_RELATIVE_PATH=/sso', 'KC_HTTP_PORT=8180', 'UNRELATED_SECRET=hidden']}}
        self.assertEqual(theme.readiness_url(row, '172.20.0.4'),
                         'http://172.20.0.4:8180/sso/realms/master/.well-known/openid-configuration')
        self.assertEqual(theme.readiness_url({'Config': {}}, '172.20.0.4'),
                         'http://172.20.0.4:8080/realms/master/.well-known/openid-configuration')
        for settings in (['KC_HTTP_RELATIVE_PATH=/../escape'], ['KC_HTTP_RELATIVE_PATH=//host'],
                         ['KC_HTTP_PORT=0'], ['KC_HTTP_PORT=70000']):
            with self.subTest(settings=settings), self.assertRaises(RuntimeError):
                theme.readiness_url({'Config': {'Env': settings}}, '172.20.0.4')

    def test_idp_readiness_honors_cli_http_port_equals_and_split_forms(self):
        theme = theme_module()
        for arguments in (['start', '--http-port=8180', '--import-realm'],
                          ['start', '--http-port', '8180', '--import-realm']):
            with self.subTest(arguments=arguments):
                row = {'Args': arguments, 'Config': {'Env': ['KC_HTTP_RELATIVE_PATH=/sso']}}
                self.assertEqual(theme.readiness_url(row, '172.20.0.4'),
                                 'http://172.20.0.4:8180/sso/realms/master/.well-known/openid-configuration')

    def test_idp_readiness_honors_cli_http_relative_path_equals_and_split_forms(self):
        theme = theme_module()
        for arguments in (['start', '--http-relative-path=/sso'],
                          ['start', '--http-relative-path', '/sso']):
            with self.subTest(arguments=arguments):
                row = {'Args': arguments, 'Config': {'Env': ['KC_HTTP_PORT=8180']}}
                self.assertEqual(theme.readiness_url(row, '172.20.0.4'),
                                 'http://172.20.0.4:8180/sso/realms/master/.well-known/openid-configuration')

    def test_idp_readiness_cli_http_settings_take_precedence_over_environment(self):
        theme = theme_module()
        for settings in (['KC_HTTP_PORT=8080', 'KC_HTTP_RELATIVE_PATH=/old'],
                         ['KC_HTTP_PORT=invalid', 'KC_HTTP_RELATIVE_PATH=invalid']):
            with self.subTest(settings=settings):
                row = {'Args': ['start', '--http-port', '8180', '--http-relative-path=/sso/'],
                       'Config': {'Env': settings}}
                self.assertEqual(theme.readiness_url(row, '172.20.0.4'),
                                 'http://172.20.0.4:8180/sso/realms/master/.well-known/openid-configuration')

    def test_idp_readiness_rejects_missing_invalid_and_duplicate_cli_http_values(self):
        theme = theme_module()
        for arguments in (['start', '--http-port'], ['start', '--http-port', '--import-realm'],
                          ['start', '--http-port='], ['start', '--http-port=abc'],
                          ['start', '--http-port=0'], ['start', '--http-port=65536'],
                          ['start', '--http-relative-path'], ['start', '--http-relative-path='],
                          ['start', '--http-relative-path=//host'], ['start', '--http-relative-path=/../escape'],
                          ['start', '--http-relative-path=/sso?query'], ['start', '--http-relative-path=/sso#fragment'],
                          ['start', '--http-port=8180', '--http-port', '8181'],
                          ['start', '--http-relative-path=/sso', '--http-relative-path=/sso']):
            with self.subTest(arguments=arguments), self.assertRaises(RuntimeError):
                theme.readiness_url({'Args': arguments, 'Config': {}}, '172.20.0.4')

    def test_idp_readiness_matches_exact_http_options_only(self):
        theme = theme_module()
        row = {'Args': ['start', '--http-port-extra=8180', '--http-relative-path-extra=/other'],
               'Config': {'Env': ['KC_HTTP_PORT=8080', 'KC_HTTP_RELATIVE_PATH=/sso']}}
        self.assertEqual(theme.readiness_url(row, '172.20.0.4'),
                         'http://172.20.0.4:8080/sso/realms/master/.well-known/openid-configuration')

    def test_idp_readiness_rejects_unstructured_cli_arguments(self):
        theme = theme_module()
        for arguments in ('start --http-port=8180', {'--http-port': '8180'}, [None], ['start', 8180]):
            with self.subTest(arguments=arguments), self.assertRaises(RuntimeError):
                theme.readiness_url({'Args': arguments, 'Config': {}}, '172.20.0.4')

    def test_mount_order_does_not_change_container_fingerprint(self):
        theme = theme_module()
        row = self.row(Path('/opt/jjdguard/releases/test'))
        row['Mounts'].append({'Destination': '/config', 'Source': '/managed/config', 'Type': 'bind', 'RW': False})
        reordered = copy.deepcopy(row)
        reordered['Mounts'].reverse()
        self.assertEqual(theme.fingerprint(row), theme.fingerprint(reordered))


class ChatThemeTransactionTests(unittest.TestCase):
    manifest = ChatThemeScopeTests.manifest
    row = ChatThemeScopeTests.row

    def setUp(self):
        self.theme = theme_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'managed'
        self.installed = self.root/'releases/test'
        self.target = self.installed/'deploy/docker-compose/chat/keycloak-themes/jjdguard'
        self.target.mkdir(parents=True)
        (self.root/'current').symlink_to(self.installed)
        self.media = self.root/'development-releases/dev-test'
        self.media.mkdir(parents=True)
        self.assets = ChatThemeScopeTests.versioned_assets()
        for name in ('login/theme.properties', 'login/resources/css/jjdguard.css',
                     'login/resources/img/jjdguard-logo.svg',
                     'login/messages/messages_en.properties', 'login/messages/messages_zh_CN.properties'):
            path = self.target/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('old '+name).encode())
            path.chmod(0o644)
        (self.target/'account').mkdir()
        (self.target/'account/untouched.txt').write_bytes(b'untouched account theme')
        self.manifest_data = self.manifest()
        self.manifest_data['theme_files'] = {name: self.digest(value) for name, value in self.assets.items()}
        with tarfile.open(self.media/'theme.tar', 'w') as archive:
            for name, value in sorted(self.assets.items()):
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        for name, field in (('vm_development_apply.py', 'apply_script_sha256'),
                            ('vm_chat_theme_release.py', 'theme_script_sha256')):
            (self.media/name).write_bytes(b'fixture frozen helper')
            self.manifest_data[field] = vm.digest(self.media/name)
        self.manifest_data['theme_archive_sha256'] = vm.digest(self.media/'theme.tar')
        (self.media/'manifest.json').write_text(json.dumps(self.manifest_data))
        self.root.chmod(0o755)
        for path in self.root.rglob('*'):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        self.rows = [self.row(self.installed), dict(Id='3'*64, Image='sha256:'+'4'*64,
                     Config={'Labels': {'com.docker.compose.service': 'web-console'}},
                     State={'Status': 'running', 'StartedAt': 'untouched'}, RestartCount=0)]
        self.rows[0]['Config']['User'] = str(os.getuid())
        self.calls = []
        self.starts = 0
        self.fail_start = False
        self.patches = [patch.object(vm, 'ROOT', self.root), patch.object(self.theme, 'inspect_all', lambda: copy.deepcopy(self.rows)),
                        patch.object(vm, 'run', self.docker_run), patch.object(self.theme.ThemeRelease, 'ready', lambda *args: None)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        owner_token = vm.INSTALL_OWNER.set((os.getuid(), os.getgid()))
        self.addCleanup(vm.INSTALL_OWNER.reset, owner_token)
        self.release = self.theme.ThemeRelease(self.media, vm.digest(self.media/'manifest.json'))
        self.before = self.theme.tree_snapshot(self.target, self.installed)
        self.other_before = copy.deepcopy(self.rows[1])

    @staticmethod
    def digest(value):
        import hashlib
        return hashlib.sha256(value).hexdigest()

    def docker_run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['docker', 'stop']:
            self.rows[0]['State']['Status'] = 'exited'
        elif argv[:2] == ['docker', 'start']:
            self.starts += 1
            if self.fail_start:
                self.fail_start = False
                raise RuntimeError('injected IDP start failure')
            self.rows[0]['State'].update(Status='running', StartedAt='start-'+str(self.starts))
        else:
            raise AssertionError('unreviewed runtime command: '+repr(argv))
        return argv[-1]

    def assert_restored(self):
        self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), self.before)
        self.assertFalse((self.target/'login/resources/css/jjdguard-portal-20261005.css').exists())
        self.assertFalse((self.target/'login/resources/img/jjdguard-logo-portal-20261005.svg').exists())
        self.assertEqual(self.rows[1], self.other_before)
        self.assertEqual(self.rows[0]['State']['Status'], 'running')
        self.assertFalse(self.release.pointer.exists())
        self.assertFalse((self.media/'receipt.json').exists())

    def test_real_atomic_apply_and_pinned_rollback_preserve_bytes_owner_modes_and_other_services(self):
        self.release.stage()
        with patch('os.chown', side_effect=AssertionError('ownership changes forbidden')):
            self.release.apply()
            published = self.theme.tree_snapshot(self.target, self.installed)
            self.assertEqual(published, self.release.candidate_tree(self.before))
            for name in ('login/resources/css/jjdguard.css', 'login/resources/img/jjdguard-logo.svg'):
                self.assertEqual(published['files'][name], self.before['files'][name])
            for name in ('login/resources/css/jjdguard-portal-20261005.css',
                         'login/resources/img/jjdguard-logo-portal-20261005.svg'):
                self.assertNotIn(name, self.before['files'])
                self.assertEqual((self.target/name).read_bytes(), self.assets[name])
            self.assertEqual(self.rows[1], self.other_before)
            self.assertTrue(self.release.pointer.exists())
            checksum = vm.digest(self.media/'receipt.json')
            self.release.rollback(checksum)
        self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), self.before)
        self.assertFalse((self.target/'login/resources/css/jjdguard-portal-20261005.css').exists())
        self.assertFalse((self.target/'login/resources/img/jjdguard-logo-portal-20261005.svg').exists())
        self.assertFalse(self.release.pointer.exists())
        self.assertEqual(self.rows[1], self.other_before)
        self.assertTrue((self.media/'rollback-receipt.json').exists())

    def test_partial_atomic_write_failure_removes_new_versioned_resources_and_restores_old_files(self):
        self.release.stage()
        atomic = vm.atomic_bytes
        def fail(path, content, **kwargs):
            if path == self.target/'login/resources/img/jjdguard-logo-portal-20261005.svg' and content == self.assets['login/resources/img/jjdguard-logo-portal-20261005.svg']:
                raise RuntimeError('injected logo write failure')
            return atomic(path, content, **kwargs)
        with patch.object(vm, 'atomic_bytes', fail), self.assertRaisesRegex(RuntimeError, 'original theme and runtime restored'):
            self.release.apply()
        self.assert_restored()

    def test_write_failure_after_both_new_resources_restores_entire_legacy_tree(self):
        self.release.stage()
        atomic = vm.atomic_bytes
        def fail(path, content, **kwargs):
            if path == self.target/'login/theme.properties' and content == self.assets['login/theme.properties']:
                for name in ('login/resources/css/jjdguard-portal-20261005.css',
                             'login/resources/img/jjdguard-logo-portal-20261005.svg'):
                    self.assertEqual((self.target/name).read_bytes(), self.assets[name])
                raise RuntimeError('injected properties write failure after new resources')
            return atomic(path, content, **kwargs)
        with patch.object(vm, 'atomic_bytes', fail), self.assertRaisesRegex(RuntimeError, 'original theme and runtime restored'):
            self.release.apply()
        self.assert_restored()

    def test_partial_write_failure_removes_new_message_directory_as_well_as_resources(self):
        for path in (self.target/'login/messages').iterdir():
            path.unlink()
        (self.target/'login/messages').rmdir()
        self.before = self.theme.tree_snapshot(self.target, self.installed)
        self.release.stage()
        atomic = vm.atomic_bytes
        def fail(path, content, **kwargs):
            if path == self.target/'login/resources/img/jjdguard-logo-portal-20261005.svg' and content == self.assets['login/resources/img/jjdguard-logo-portal-20261005.svg']:
                self.assertTrue((self.target/'login/messages').is_dir())
                raise RuntimeError('injected logo write failure after new message directory')
            return atomic(path, content, **kwargs)
        with patch.object(vm, 'atomic_bytes', fail), self.assertRaisesRegex(RuntimeError, 'original theme and runtime restored'):
            self.release.apply()
        self.assert_restored()
        self.assertFalse((self.target/'login/messages').exists())

    def test_idp_start_failure_restores_original_theme_then_restarts_it(self):
        self.release.stage()
        self.fail_start = True
        with self.assertRaisesRegex(RuntimeError, 'original theme and runtime restored'):
            self.release.apply()
        self.assertEqual(self.starts, 2)
        self.assert_restored()

    def test_receipt_publication_failure_recovers_original_assets_without_success_pointer(self):
        self.release.stage()
        atomic = vm.atomic_bytes
        def fail(path, content, **kwargs):
            if path == self.release.pointer:
                raise RuntimeError('injected success pointer failure')
            return atomic(path, content, **kwargs)
        with patch.object(vm, 'atomic_bytes', fail), self.assertRaisesRegex(RuntimeError, 'original theme and runtime restored'):
            self.release.apply()
        self.assert_restored()

    def test_changed_stage_evidence_is_rejected_before_stopping_idp(self):
        self.release.stage()
        (self.media/'state/before.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'stage evidence changed'):
            self.release.apply()
        self.assertEqual(self.calls, [])

    def test_invalid_idp_http_arguments_are_rejected_before_stopping_idp(self):
        self.rows[0]['Args'] = ['start', '--http-port']
        with self.assertRaisesRegex(RuntimeError, 'IDP CLI HTTP'):
            self.release.stage()
        self.assertEqual(self.calls, [])

    def test_replaced_bind_directory_inode_is_rejected_before_stopping_idp(self):
        self.release.stage()
        previous = self.target.with_name('old-theme')
        self.target.rename(previous)
        import shutil
        shutil.copytree(previous, self.target)
        with self.assertRaisesRegex(RuntimeError, 'stage drifted'):
            self.release.apply()
        self.assertEqual(self.calls, [])

    def test_tampered_asset_archive_is_rejected_before_runtime_commands(self):
        self.release.stage()
        (self.media/'theme.tar').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'frozen theme media differs'):
            self.release.apply()
        self.assertEqual(self.calls, [])

    def test_symlinked_existing_theme_file_is_rejected_before_stopping_idp(self):
        path = self.target/'login/resources/css/jjdguard.css'
        path.unlink()
        path.symlink_to(self.target/'account/untouched.txt')
        with self.assertRaisesRegex(RuntimeError, 'owner or type differs'):
            self.release.stage()
        self.assertEqual(self.calls, [])

    def test_symlinked_new_versioned_resource_targets_are_rejected_before_stopping_idp(self):
        for name in ('login/resources/css/jjdguard-portal-20261005.css',
                     'login/resources/img/jjdguard-logo-portal-20261005.svg'):
            with self.subTest(name=name):
                path = self.target/name
                self.assertFalse(path.exists())
                path.symlink_to(self.target/'account/untouched.txt')
                with self.assertRaisesRegex(RuntimeError, 'owner or type differs'):
                    self.release.stage()
                self.assertEqual(self.calls, [])
                path.unlink()

    def test_apply_preserves_original_modes_under_private_process_umask(self):
        self.release.stage()
        mask = os.umask(0o077)
        try:
            self.release.apply()
            self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), self.release.candidate_tree(self.before))
        finally:
            os.umask(mask)

    def test_failed_rollback_restarts_active_theme_and_keeps_pinned_receipt(self):
        self.release.stage()
        self.release.apply()
        candidate = self.theme.tree_snapshot(self.target, self.installed)
        pointer = self.release.pointer.read_bytes()
        checksum = vm.digest(self.media/'receipt.json')
        self.fail_start = True
        with self.assertRaisesRegex(RuntimeError, 'active theme and runtime restored'):
            self.release.rollback(checksum)
        self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), candidate)
        self.assertEqual(self.release.pointer.read_bytes(), pointer)
        self.assertEqual(vm.digest(self.media/'receipt.json'), checksum)
        self.assertEqual(self.rows[0]['State']['Status'], 'running')
        self.assertEqual(self.rows[1], self.other_before)
        self.assertFalse((self.media/'rollback-receipt.json').exists())
        self.release.rollback(checksum)
        self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), self.before)

    def test_guest_bootstrap_authenticates_helpers_and_uses_installation_owner_chain(self):
        for path in self.media.iterdir():
            path.chmod(0o600)
        self.media.chmod(0o700)
        code = self.theme.apply_guest_code('dev-test', self.release.manifest_sha, 'stage')
        code = code.replace('Path("/opt/jjdguard")', 'Path('+repr(str(self.root))+')')
        code = code.replace('not parent.is_symlink() and info.st_uid == 0',
                            'not parent.is_symlink() and info.st_uid == os.getuid()')
        with patch('subprocess.run') as execute:
            exec(compile(code, '<theme-owner-bootstrap>', 'exec'), {})
        execute.assert_called_once()
        command = execute.call_args.args[0]
        self.assertIn('vm_chat_theme_release.py', ' '.join(command))
        self.assertIn('--install-owner-uid', command)
        self.assertNotIn('PYTHONPATH', execute.call_args.kwargs['env'])
        (self.media/'json.py').write_text('must not import')
        with patch('subprocess.run') as execute, self.assertRaisesRegex(RuntimeError, 'unrecorded theme media'):
            exec(compile(code, '<theme-owner-bootstrap>', 'exec'), {})
        execute.assert_not_called()

    def test_frozen_build_media_contains_exact_login_assets_without_images(self):
        source = Path(self.temp.name)/'source'
        root = source/self.theme.THEME_PATH
        for name, value in self.assets.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        for name in ('vm_development_apply.py', 'vm_chat_theme_release.py'):
            path = source/'deploy/release'/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'frozen source helper')
        output = Path(self.temp.name)/'media-build'
        manifest = self.manifest()
        self.theme.build_theme_media(source, output, manifest)
        self.assertEqual({path.name for path in output.iterdir()}, set(self.theme.MEDIA_FILES))
        self.assertEqual(self.theme.read_theme_archive((output/'theme.tar').read_bytes(), manifest['theme_files']), self.assets)
        self.assertEqual(manifest['services'], {})
        self.assertEqual(manifest['migrations'], {})

    def test_inspect_mount_reordering_between_stage_and_apply_is_not_runtime_drift(self):
        self.rows[1]['Mounts'] = [
            {'Destination': '/config', 'Source': '/managed/config', 'Type': 'bind', 'RW': False},
            {'Destination': '/cert', 'Source': '/managed/cert', 'Type': 'bind', 'RW': False},
        ]
        self.release.stage()
        self.rows[1]['Mounts'].reverse()
        self.release.apply()
        self.assertEqual(self.theme.tree_snapshot(self.target, self.installed), self.release.candidate_tree(self.before))
        self.assertTrue(self.release.pointer.exists())

    def test_real_non_target_mount_drift_still_rejects_before_stopping_idp(self):
        self.rows[1]['Mounts'] = [
            {'Destination': '/config', 'Source': '/managed/config', 'Type': 'bind', 'RW': False},
        ]
        self.release.stage()
        baseline = copy.deepcopy(self.rows[1])
        for changes in ({'Source': '/other/config'}, {'Destination': '/other'}, {'RW': True}, {'Type': 'volume'}):
            with self.subTest(changes=changes):
                self.rows[1] = copy.deepcopy(baseline)
                self.rows[1]['Mounts'][0].update(changes)
                with self.assertRaisesRegex(RuntimeError, 'stage drifted'):
                    self.release.apply()
                self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
