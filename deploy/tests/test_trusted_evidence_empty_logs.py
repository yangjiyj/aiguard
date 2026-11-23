import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("trusted_evidence", ROOT / "deploy/offline-installer/verify-promoted-release.py")
trusted = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = trusted
spec.loader.exec_module(trusted)

class EmptyLogEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.release = self.root / "release"
        self.release.mkdir()
        (self.release / "evidence").mkdir()
        self.fd = trusted.open_absolute_directory(self.release, "test release")
        self.addCleanup(os.close, self.fd)

    def stage(self, relative, data, expected=None, symlink=False):
        path = self.release / "evidence" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if symlink:
            target = self.root / "external"
            target.write_bytes(data)
            path.symlink_to(target)
        else:
            path.write_bytes(data)
        stage = self.root / "stage"
        stage.mkdir()
        index = {"schema": "jjdguard-acceptance-evidence-index/v1",
                 "artifact": {}, "release": {},
                 "entries": [{"path": relative, "sha256": expected or hashlib.sha256(data).hexdigest()}]}
        trusted.stage_promoted_evidence(self.fd, index, stage)
        return stage / "evidence" / relative

    def rejected(self, *args, **kwargs):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.stage(*args, **kwargs)

    def test_indexed_empty_stdout_log_is_copied_and_hashed(self):
        staged = self.stage("logs/clean-install.business-probe.log", b"")
        self.assertEqual(staged.read_bytes(), b"")
        self.assertEqual(staged.stat().st_size, 0)

    def test_nonempty_stdout_still_passes(self):
        self.assertEqual(self.stage("logs/scenario.log", b"actual pass\n").read_bytes(), b"actual pass\n")

    def test_empty_log_cannot_replace_nonempty_signed_log(self):
        self.rejected("logs/scenario.log", b"", expected=hashlib.sha256(b"original\n").hexdigest())

    def test_nonempty_log_cannot_replace_empty_signed_log(self):
        self.rejected("logs/scenario.log", b"tampered", expected=hashlib.sha256(b"").hexdigest())

    def test_empty_record_is_rejected(self):
        self.rejected("records/clean-install.json", b"")

    def test_empty_baseline_is_rejected(self):
        self.rejected("home-migration-baseline.json", b"")

    def test_empty_non_log_is_rejected(self):
        self.rejected("logs/summary.json", b"")

    def test_symlink_to_empty_log_is_rejected(self):
        self.rejected("logs/scenario.log", b"", symlink=True)

    def test_missing_indexed_log_is_rejected(self):
        stage = self.root / "stage"; stage.mkdir()
        index = {"schema":"jjdguard-acceptance-evidence-index/v1", "artifact":{}, "release":{},
                 "entries":[{"path":"logs/missing.log","sha256":hashlib.sha256(b"").hexdigest()}]}
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            trusted.stage_promoted_evidence(self.fd,index,stage)


class RealInstallerHeaderABI(unittest.TestCase):
    def test_production_install_command_reaches_real_header_integrity_gate(self):
        from unittest.mock import patch
        real_run = trusted.subprocess.run
        observations = []
        def captured(command, **kwargs):
            result = real_run(command, **dict(kwargs, stdout=-1, stderr=-1))
            observations.append(result)
            return result
        with patch.dict(os.environ, {}, clear=True), patch.object(trusted.os, "geteuid", return_value=0), patch.object(trusted.subprocess, "run", side_effect=captured):
            status = trusted.run_verified_installer(ROOT / "deploy/offline-installer/self-extracting-header.sh", False)
        self.assertEqual(len(observations), 1)
        # The unsealed real template must fail integrity, after accepting the
        # install command. Exit 64 is the real header's unsupported-argument gate.
        self.assertEqual(status, 40)

if __name__ == "__main__":
    unittest.main()
