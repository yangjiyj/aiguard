#!/usr/bin/env python3
"""Render real upgrade/rollback overrides with Compose without touching Docker state."""
import json, os, pathlib, re, shutil, subprocess, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[2]
IMAGE = 'sha256:' + '1' * 64
CORE = ['gateway-core', 'control-plane', 'security-engine', 'web-console', 'worker']

class ProxyOverrideBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which('docker')
        if not cls.docker:
            raise RuntimeError('Docker Compose CLI required for render-only regression')
        subprocess.run([cls.docker, 'compose', 'version'], check=True, stdout=subprocess.PIPE)

    def generate(self, directory, kind, proxies, malformed=False):
        dc = directory / 'deploy/docker-compose'
        dc.mkdir(parents=True)
        (dc / '.upgrade').mkdir()
        base = dc / 'docker-compose.offline.yml'
        names = CORE + proxies
        base.write_text('services:\n' + ''.join('  ' + n + ':\n    image: example.invalid/base:fixture\n' + ('    profiles: [vm]\n' if n == 'proxy-server-vm' else '') for n in names) if not malformed else 'services: [invalid\n')
        (dc / '.env').write_text('')
        wrapper = dc / 'compose-wrapper.sh'
        wrapper.write_text('#!/bin/sh\nexec ' + __import__('shlex').quote(self.docker) + ' compose "$@"\n')
        wrapper.chmod(0o755)
        source = ROOT / ('deploy/docker-compose/upgrade.sh' if kind == 'upgrade' else 'deploy/offline-installer/jjdctl')
        name = 'write_override' if kind == 'upgrade' else 'write_rollback_image_override'
        body = re.search(r'^' + name + r'\(\) \{\n.*?^\}\n', source.read_text(), re.M | re.S)
        self.assertIsNotNone(body)
        functions = directory / 'function.sh'
        functions.write_text(body[0])
        output = dc / '.upgrade/compose.upgrade.yml'
        if malformed:
            output.write_text('prior-override-preserved\n')
        call = 'write_override "$IMAGE" "$IMAGE" "$IMAGE" "$IMAGE" "$IMAGE" "$IMAGE"' if kind == 'upgrade' else 'write_rollback_image_override "$DC"'
        script = 'source "$1"; fail() { echo failed >&2; return 1; }; die() { echo failed >&2; return 1; }; ' + call
        env = {k: v for k, v in os.environ.items() if not k.startswith('COMPOSE_')}
        env.update(IMAGE=IMAGE, DC=str(dc), ENV_FILE=str(dc / '.env'), COMPOSE_FILE=str(base), COMPOSE_WRAPPER=str(wrapper), OVERRIDE_DIR=str(output.parent), OVERRIDE_FILE=str(output), GATEWAY_CORE_IMAGE=IMAGE, CONTROL_PLANE_IMAGE=IMAGE, SECURITY_ENGINE_IMAGE=IMAGE, PROXY_SERVER_IMAGE=IMAGE, WEB_CONSOLE_IMAGE=IMAGE, WORKER_IMAGE=IMAGE, LLM_JUDGE_IMAGE='', TIER1_CLASSIFIER_IMAGE='', CHAT_PORTAL_UI_IMAGE='', CHAT_PORTAL_PROXY_IMAGE='')
        result = subprocess.run(['bash', '-Eeuo', 'pipefail', '-c', script, 'regression', str(functions)], cwd=dc, env=env, capture_output=True)
        return result, output, base, names, env

    def test_only_declared_proxy_services_reach_rendered_configuration(self):
        for kind in ['upgrade', 'rollback']:
            for proxies in [['proxy-server'], ['proxy-server-vm'], ['proxy-server', 'proxy-server-vm']]:
                with self.subTest(kind=kind, proxies=proxies), tempfile.TemporaryDirectory() as temp:
                    result, output, base, names, env = self.generate(pathlib.Path(temp), kind, proxies)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    rendered = subprocess.run([self.docker, 'compose', '--profile', '*', '-f', str(base), '-f', str(output), 'config', '--format', 'json'], env=env, capture_output=True, check=True)
                    services = json.loads(rendered.stdout)['services']
                    self.assertEqual(set(services), set(names), 'override introduced a service absent from its base')
                    for name in proxies:
                        self.assertEqual(services[name]['image'], IMAGE)
                    if 'proxy-server-vm' in proxies:
                        self.assertEqual(services['proxy-server-vm']['profiles'], ['vm'])

    def test_bad_base_is_rejected_before_existing_override_changes(self):
        for kind in ['upgrade', 'rollback']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                result, output, *_ = self.generate(pathlib.Path(temp), kind, ['proxy-server'], malformed=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_text(), 'prior-override-preserved\n')

if __name__ == '__main__':
    unittest.main(verbosity=2)
