"""Exercise offline port allocation -> persisted client URL without starting services."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "docker-compose/deploy-offline.sh"


def function(name):
    match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", SOURCE.read_text(), re.M | re.S)
    if match is None:
        raise AssertionError("installer function missing: " + name)
    return match.group(0)


class PublicBaseURLTest(unittest.TestCase):
    def test_all_default_ports_occupied_uses_allocated_gateway_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Fixture ss marks the customer's existing default ports as occupied.
            ss = root / "ss"
            ss.write_text("#!/bin/sh\ncase \"$*\" in *':8080'|*':8081'|*':8082'|*':8083') echo \"$*\" ;; esac\n")
            ss.chmod(0o755)
            wrapper = root / "compose"
            wrapper.write_text("#!/bin/sh\ncat > \"$SQL_CAPTURE\"\n")
            env = dict(os.environ, PATH=tmp + ":" + os.environ["PATH"],
                       COMPOSE_WRAPPER=str(wrapper), SQL_CAPTURE=str(root / "seed.sql"))
            script = "\n".join([
                "set -eu", "RESERVED_PORTS=",
                function("port_in_use"), function("allocate_port"), function("seed_public_base_url"),
                "detect_host() { printf customer.example; }",
                "allocate_port GATEWAY_PORT 8080",
                "allocate_port PROXY_PORT 8082",
                "allocate_port CONTROL_PORT 8081",
                '[ "$GATEWAY_PORT" = 8084 ]',
                '[ "$PROXY_PORT" = 8085 ]',
                '[ "$CONTROL_PORT" = 8086 ]',
                "seed_public_base_url",
            ])
            result = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            sql = (root / "seed.sql").read_text()
            self.assertIn("'http://customer.example:8084/v1'", sql)
            self.assertNotIn("customer.example:8080", sql)
            # Customer overrides must not be overwritten on reinstall.
            self.assertIn("ON CONFLICT (key) DO NOTHING", sql)


if __name__ == "__main__":
    unittest.main()
