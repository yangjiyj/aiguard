import pytest

from training import license_gate as lg


def test_allowed_licenses_whitelist_exact_set():
    # 红线：只允许 MIT/Apache/BSD 系；Llama/gated 绝不在内
    assert lg.ALLOWED_LICENSES == {
        "apache-2.0",
        "mit",
        "bsd-3-clause",
        "bsd-2-clause",
    }


@pytest.mark.parametrize(
    "raw",
    ["apache-2.0", "Apache-2.0", "  MIT  ", "BSD-3-Clause", "bsd-2-clause"],
)
def test_normalize_then_check_passes_for_whitelisted(raw):
    # 大小写/空白归一化后命中白名单 → 不抛
    lg.assert_license_allowed(raw, model_id="intfloat/multilingual-e5-small")


def test_check_rejects_llama_community_license():
    with pytest.raises(lg.LicenseNotAllowedError) as ei:
        lg.assert_license_allowed("llama3", model_id="meta-llama/Prompt-Guard-2-86M")
    msg = str(ei.value)
    assert "llama3" in msg
    assert "meta-llama/Prompt-Guard-2-86M" in msg
    assert "apache-2.0" in msg  # 报错须列出白名单，给修复方向


def test_check_rejects_unknown_license():
    with pytest.raises(lg.LicenseNotAllowedError):
        lg.assert_license_allowed("cc-by-nc-4.0", model_id="some/model")


def test_check_rejects_missing_license():
    # license 字段缺失（None/空串）= 不可证明合规 → 阻断（fail-closed，许可红线）
    with pytest.raises(lg.LicenseNotAllowedError) as ei:
        lg.assert_license_allowed(None, model_id="some/model")
    assert "缺失" in str(ei.value) or "missing" in str(ei.value).lower()
    with pytest.raises(lg.LicenseNotAllowedError):
        lg.assert_license_allowed("   ", model_id="some/model")


def test_license_from_hf_config_reads_license_field():
    # 从 HF config dict 抽 license 字段（兼容 cardData.license 与顶层 license）
    assert lg.license_from_hf_config({"license": "apache-2.0"}) == "apache-2.0"
    assert lg.license_from_hf_config({"cardData": {"license": "mit"}}) == "mit"
    assert lg.license_from_hf_config({}) is None


def test_assert_model_license_allowed_end_to_end_from_config():
    # 闸的入口组合：从 config 抽 license → 检查；白名单过、非白名单抛
    lg.assert_model_license_allowed(
        {"license": "Apache-2.0"}, model_id="intfloat/multilingual-e5-small"
    )
    with pytest.raises(lg.LicenseNotAllowedError):
        lg.assert_model_license_allowed(
            {"license": "llama3"}, model_id="meta-llama/Prompt-Guard-2-86M"
        )
