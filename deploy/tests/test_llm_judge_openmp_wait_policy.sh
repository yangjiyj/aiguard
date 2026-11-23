#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

# Execute the real source entrypoint with an exec spy. No model/server is run.
sh -n "$ROOT/deploy/docker-compose/llm-judge/entrypoint.sh"
python3 - "$ROOT/deploy/docker-compose/llm-judge/entrypoint.sh" <<'PY_OPENMP_POLICY'
import json
import os
import pathlib
import subprocess
import sys
import tempfile

entrypoint = pathlib.Path(sys.argv[1]).resolve()
capture = ("import json,os,sys;"
           "print(json.dumps({'wait':os.getenv('OMP_WAIT_POLICY'),"
           "'spin':os.getenv('GOMP_SPINCOUNT'),'argv':sys.argv[1:]}))")
spy = 'exec() { "$PROBE_PYTHON" -c "$PROBE_CAPTURE" "$@"; }; . "$1"'
with tempfile.TemporaryDirectory(prefix="judge-policy-") as directory:
    model = pathlib.Path(directory) / "synthetic.gguf"
    model.write_bytes(b"not-a-model-exec-is-intercepted")
    fixed = {
        "PATH": "/usr/bin:/bin", "HOME": directory,
        "PROBE_PYTHON": sys.executable, "PROBE_CAPTURE": capture,
        "JUDGE_MODEL_PATH": str(model), "JUDGE_PORT": "18080",
        "JUDGE_ALIAS": "bundled-judge", "JUDGE_CTX": "4096",
        "JUDGE_THREADS": "4", "JUDGE_PARALLEL": "2",
        "JUDGE_CACHE_RAM_MB": "1024", "JUDGE_BATCH_SIZE": "512",
        "JUDGE_UBATCH_SIZE": "128", "JUDGE_API_KEY": "synthetic-contract-key",
    }
    expected_argv = [
        "/opt/llama/llama-server", "-m", str(model),
        "--host", "0.0.0.0", "--port", "18080",
        "--alias", "bundled-judge", "-c", "4096",
        "-t", "4", "--threads-batch", "4", "--parallel", "2",
        "--cache-ram", "1024", "--batch-size", "512",
        "--ubatch-size", "128", "--api-key", "synthetic-contract-key",
    ]
    cases = [
        ({}, "PASSIVE", None),
        ({"OMP_WAIT_POLICY": ""}, "PASSIVE", None),
        ({"OMP_WAIT_POLICY": "ACTIVE"}, "ACTIVE", None),
        ({"OMP_WAIT_POLICY": "PASSIVE"}, "PASSIVE", None),
        ({"GOMP_SPINCOUNT": "17"}, "PASSIVE", "17"),
    ]
    for overrides, expected_wait, expected_spin in cases:
        result = subprocess.run(
            ["/bin/bash", "-c", spy, "entrypoint-policy-test", str(entrypoint)],
            env={**fixed, **overrides}, capture_output=True, text=True, check=True,
        )
        actual = json.loads(result.stdout)
        assert actual["wait"] == expected_wait, (overrides, actual["wait"], expected_wait)
        assert actual["spin"] == expected_spin, (overrides, actual["spin"], expected_spin)
        assert actual["argv"] == expected_argv, actual["argv"]
    missing = subprocess.run(
        ["/bin/bash", "-c", spy, "entrypoint-policy-test", str(entrypoint)],
        env={**fixed, "JUDGE_MODEL_PATH": str(model) + ".absent"},
        capture_output=True, text=True,
    )
    assert missing.returncode == 1 and "[fatal]" in missing.stderr and not missing.stdout
print("PASS actual entrypoint wait-policy/default/override/argv/model-failure cases=6")
PY_OPENMP_POLICY

printf 'PASS test_llm_judge_openmp_wait_policy\n'
