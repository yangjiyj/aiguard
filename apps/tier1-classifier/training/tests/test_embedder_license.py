import pytest
from pathlib import Path

from training import embedder_license as el
from training.license_gate import LicenseNotAllowedError


def test_default_loader_is_local_only_and_never_queries_hugging_face_hub():
    source = Path(el.__file__).read_text(encoding="utf-8")
    assert "local_files_only=True" in source
    assert "huggingface_hub" not in source
    assert "model_info(" not in source


def _loader(mapping):
    """注入式 HF config 加载器：model_id -> config dict。"""
    def _load(model_id):
        if model_id not in mapping:
            raise KeyError(model_id)
        return mapping[model_id]
    return _load


def test_precheck_passes_for_apache_embedder():
    loader = _loader({"intfloat/multilingual-e5-small": {"license": "apache-2.0"}})
    # 不抛，且回传归一化后的 license 供日志/审计
    lic = el.precheck_embedder_license(
        "intfloat/multilingual-e5-small", config_loader=loader
    )
    assert lic == "apache-2.0"


def test_precheck_passes_for_mit_bge():
    loader = _loader({"BAAI/bge-small-zh": {"license": "mit"}})
    assert el.precheck_embedder_license("BAAI/bge-small-zh", config_loader=loader) == "mit"


def test_precheck_blocks_llama_before_any_encode():
    loader = _loader({"meta-llama/Prompt-Guard-2-86M": {"license": "llama3"}})
    with pytest.raises(LicenseNotAllowedError) as ei:
        el.precheck_embedder_license(
            "meta-llama/Prompt-Guard-2-86M", config_loader=loader
        )
    assert "meta-llama/Prompt-Guard-2-86M" in str(ei.value)


def test_precheck_blocks_when_config_has_no_license():
    loader = _loader({"some/model": {}})
    with pytest.raises(LicenseNotAllowedError):
        el.precheck_embedder_license("some/model", config_loader=loader)


def test_precheck_blocks_when_config_unavailable():
    # config 加载本身失败（离线/拼写错）→ 不可证明合规 → 阻断（fail-closed）
    loader = _loader({})  # 任何 model_id 都 KeyError
    with pytest.raises(LicenseNotAllowedError) as ei:
        el.precheck_embedder_license("typo/model", config_loader=loader)
    assert "无法获取" in str(ei.value) or "config" in str(ei.value).lower()
