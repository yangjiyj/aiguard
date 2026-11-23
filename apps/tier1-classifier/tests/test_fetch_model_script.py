import os
import stat

HERE = os.path.dirname(__file__)
SCRIPT = os.path.abspath(os.path.join(HERE, "..", "scripts", "fetch-model.sh"))


def test_script_exists_and_executable():
    assert os.path.isfile(SCRIPT)
    mode = os.stat(SCRIPT).st_mode
    assert mode & stat.S_IXUSR  # 可执行位


def _body():
    with open(SCRIPT, "r", encoding="utf-8") as f:
        return f.read()


def test_legacy_download_entry_is_fail_closed():
    body = _body()
    assert "exit 78" in body
    assert "TIER1_OWNED_MODEL_INPUT" in body
    assert "huggingface" not in body.lower()
    assert "hf-mirror" not in body.lower()
