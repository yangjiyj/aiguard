import os

HERE = os.path.dirname(__file__)
ENV = os.path.abspath(os.path.join(HERE, "..", ".env.example"))
OFFLINE = os.path.abspath(
    os.path.join(HERE, "..", "docker-compose.offline.yml")
)


def _body():
    with open(ENV, "r", encoding="utf-8") as f:
        return f.read()


def _offline_body():
    with open(OFFLINE, "r", encoding="utf-8") as f:
        return f.read()


def test_tier1_doc_is_selftrained_opensource():
    body = _body()
    # 自训开源口径（许可干净），不得再宣称 Prompt-Guard-2（gated/Llama 许可）
    assert "Prompt-Guard" not in body
    assert "自训" in body
    # 许可白名单明示
    assert "MIT" in body or "Apache" in body


def test_tier1_env_vars_unchanged():
    body = _body()
    # 变量键名不动（compose 零改契约）
    for key in (
        "SECURITY_TIER1_ENABLED",
        "SECURITY_TIER1_URL",
        "SECURITY_TIER1_LOW_THRESHOLD",
        "SECURITY_TIER1_HIGH_THRESHOLD",
        "TIER1_EXECUTION_PROVIDER",
        "TIER1_THREADS",
        "TIER1_CPU_IMAGE",
        "TIER1_CPU_INFERENCE_CAPACITY",
        "TIER1_GPU_IMAGE",
        "TIER1_GPU_COUNT",
        "TIER1_GPU_INFERENCE_CAPACITY",
        # 第二段（SECURITY_SEMANTIC_MAX_WINDOWS 后）也必须留空，否则 autotune 的
        # resolve_real 会把它当显式值，large 档的 8/256 永远写不进去。
        "TIER1_INFERENCE_WORKERS",
        "TIER1_INFERENCE_CAPACITY",
    ):
        assert key in body


def test_tier1_profile_knobs_are_overrides_not_defaults():
    """S1: 档位旋钮写死会盖掉 autotune，把 2x16 从后门塞回去。

    引擎按 large 档的 8x256 打在途，sidecar 只有 2x16，满载时 503 被判成降级，
    而供需校验读的是 .env，照样报 within_limit。所以这些键只能以注释示例存在。
    """
    body = _body()
    for key in (
        "TIER1_CPU_THREADS",
        "TIER1_CPU_WORKERS",
        "TIER1_CPU_INFERENCE_WORKERS",
        "TIER1_CPU_INFERENCE_CAPACITY",
        "TIER1_GPU_WORKERS",
        "TIER1_GPU_INFERENCE_WORKERS",
        "TIER1_GPU_INFERENCE_CAPACITY",
    ):
        assert "\n#%s=" % key in body, "%s must stay commented out (= follow autotune)" % key
        assert "\n%s=" % key not in body, "%s must not be an active value" % key
    # “留空 = 跟随档位”必须写出来，否则运维只会看到一堆被注释掉的键。
    assert "跟随" in body
    # CUDA 的 intra-op 线程是例外：固定 1，保持生效。
    assert "\nTIER1_GPU_THREADS=1\n" in body


def test_offline_yml_tier1_doc_is_selftrained_opensource():
    # 同属离线交付包、客户可见的第二份文档：口径必须与 .env.example 一致，
    # 不得再宣称 Prompt-Guard-2（gated/Llama 许可），须写自训开源口径。
    body = _offline_body()
    assert "Prompt-Guard" not in body
    assert "自训" in body


def test_offline_yml_tier1_service_unchanged():
    # 服务名/镜像名/内部路径等功能性标识符不动（仅注释文案对齐）。
    body = _offline_body()
    for token in (
        "tier1-classifier:",
        "docker-compose-tier1-classifier:latest",
        "/classify",
    ):
        assert token in body
