import os
import stat


HERE = os.path.dirname(__file__)
SCRIPT = os.path.abspath(os.path.join(HERE, "..", "scripts", "build-baseline-model.sh"))


def test_script_exists_and_remains_explicitly_blocked():
    assert os.path.isfile(SCRIPT)
    assert os.stat(SCRIPT).st_mode & stat.S_IXUSR
    body = open(SCRIPT, encoding="utf-8").read()
    assert "set -eu" in body
    assert "exit 78" in body
    assert "TIER1_OWNED_MODEL_INPUT" in body
    assert "training.retrain" not in body
