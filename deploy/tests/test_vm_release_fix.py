"""2026-10-10 开发 VM 发布失败的回归：chat-portal-ui 丢 image.source 标签被判契约变化；3.6 GB 库恢复超时。"""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"release"))
import vm_development_apply as vm


def row(labels):
    return {"Id": "c"*64, "Image": "sha256:"+"a"*64,
            "Config": {"Labels": dict(labels), "Env": ["A=1"], "User": "portal"},
            "HostConfig": {}, "Mounts": [], "NetworkSettings": {"Networks": {}},
            "Path": "docker-entrypoint.sh", "Args": []}


class ImageSourceLabelTest(unittest.TestCase):
    def test_target_contract_ignores_image_source_provenance(self):
        old = row({"org.opencontainers.image.source": "https://gitee.com/x/y.git", "app": "portal"})
        new = row({"app": "portal"})
        self.assertEqual(vm.identity_chat_contract_hash(old, True), vm.identity_chat_contract_hash(new, True))

    def test_non_target_contract_still_detects_image_source_change(self):
        old = row({"org.opencontainers.image.source": "https://gitee.com/x/y.git"})
        new = row({})
        self.assertNotEqual(vm.identity_chat_contract_hash(old, False), vm.identity_chat_contract_hash(new, False))

    def test_target_contract_still_detects_business_label_change(self):
        self.assertNotEqual(vm.identity_chat_contract_hash(row({"app": "portal"}), True),
                            vm.identity_chat_contract_hash(row({"app": "other"}), True))


class DatabaseTimeoutTest(unittest.TestCase):
    def test_small_database_keeps_300_second_floor(self):
        self.assertEqual(vm.Release.database_timeout(10*1024*1024), 300)

    def test_large_restore_gets_more_than_the_observed_five_minutes(self):
        dump = 3685898771
        self.assertGreaterEqual(vm.Release.database_timeout(dump*4), 1800)


if __name__ == "__main__":
    unittest.main()
