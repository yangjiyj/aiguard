"""Execute the deployment benchmark against fake services; no Docker/DB access."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("latency_ms", [1000, 5000, 10000])
def test_hardware_profiles_never_modify_detection_thresholds(tmp_path, latency_ms):
    root = Path(__file__).resolve().parents[3]
    script = tmp_path / "judge-benchmark.sh"
    shutil.copy(root / "deploy/docker-compose/judge-benchmark.sh", script)
    wrapper = tmp_path / "compose-wrapper.sh"
    wrapper.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> captured.calls\ncase \"$*\" in *postgres*) cat > captured.sql;; *) exit 0;; esac\n".replace('\"', '"'))
    clock = tmp_path / "date"
    clock.write_text("#!/bin/sh\nn=$(cat clock.count 2>/dev/null || echo 0)\necho $((n + 1)) > clock.count\necho $((100000000000 + n * " + str(latency_ms) + " * 1000000))\n")
    clock.chmod(0o755)
    result = subprocess.run(["sh", str(script)], env={**os.environ, "PATH": str(tmp_path) + ":" + os.environ["PATH"]}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "captured.calls").read_text()
    assert "exec -T security-engine python -c" in calls
    assert "judge_semantic" in calls
    sql = (tmp_path / "captured.sql").read_text()
    assert "tier1_low_threshold" not in sql
    assert "tier1_high_threshold" not in sql
    assert "judge_timeout" in sql and "semantic_total_timeout" in sql
