#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
python3 - "$root" <<'PY'
import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest
SOURCE = pathlib.Path(sys.argv[1])
class ComposeWrapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="compose wrapper ")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.wrapper = self.root / "compose-wrapper.sh"
        shutil.copyfile(SOURCE / "deploy/docker-compose/compose-wrapper.sh", self.wrapper)
        (self.root / "bin").mkdir()
        (self.root / "system").mkdir()
        self.env = dict(os.environ, PATH=str(self.root / "system") + ":/usr/bin:/bin")
        self.system = self.root / "system/docker"
        self.bundled = self.root / "bin/docker-compose"
        self.write_executable(self.system, "system")
    def write_executable(self, path, label, code=0):
        path.write_text("#!/usr/bin/python3\nimport json,sys\nprint(json.dumps([" + repr(label) + "]+sys.argv[1:]))\nsys.exit(" + str(code) + ")\n")
        path.chmod(0o755)
    def run_wrapper(self, *args):
        return subprocess.run(["/bin/sh", str(self.wrapper), *args], env=self.env, text=True, capture_output=True)
    def test_bundled_preferred_and_arguments_preserved(self):
        self.write_executable(self.bundled, "bundled")
        args = ["-f", "path with spaces/a.yaml", "", "--project-name", "x;$(false)", "up", "-d"]
        result = self.run_wrapper(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["bundled"] + args)
    def test_bundled_failure_does_not_fallback(self):
        self.write_executable(self.bundled, "bundled", 37)
        result = self.run_wrapper("up")
        self.assertEqual(result.returncode, 37)
        self.assertEqual(json.loads(result.stdout), ["bundled", "up"])
    def test_nonexecutable_bundle_fails_closed(self):
        self.write_executable(self.bundled, "bundled")
        self.bundled.chmod(0o644)
        result = self.run_wrapper("up")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not executable", result.stderr)
        self.assertEqual(result.stdout, "")
    def test_source_checkout_falls_back_to_system(self):
        result = self.run_wrapper("ps", "service with spaces")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["system", "compose", "ps", "service with spaces"])
    def test_no_available_compose_fails(self):
        self.system.write_text("#!/bin/sh\nexit 1\n")
        result = self.run_wrapper("up")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker Compose", result.stderr)
unittest.main(argv=[sys.argv[0]], verbosity=2)
PY
