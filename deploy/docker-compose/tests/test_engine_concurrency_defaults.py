import re
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1]


def _engine_env(name):
    text = (COMPOSE / name).read_text(encoding="utf-8")
    return text


def test_composes_pass_web_concurrency_default_one():
    for name in ("docker-compose.yml", "docker-compose.offline.yml"):
        block = _service_block(_engine_env(name), "security-engine")
        assert "- WEB_CONCURRENCY=${SECURITY_ENGINE_WEB_CONCURRENCY:-1}" in block, name


def test_engine_worker_defaults_are_two_in_compose_and_code():
    root = COMPOSE.parents[1] / "apps" / "security-engine" / "app" / "api"
    assert 'from_env("SECURITY_INPUT", workers=2,' in (root / "check_input.py").read_text(encoding="utf-8")
    assert 'from_env("SECURITY_OUTPUT", workers=2,' in (root / "check_output.py").read_text(encoding="utf-8")
    for name in ("docker-compose.yml", "docker-compose.offline.yml"):
        text = _engine_env(name)
        assert "SECURITY_INPUT_WORKERS=${SECURITY_INPUT_WORKERS:-2}" in text
        assert "SECURITY_OUTPUT_WORKERS=${SECURITY_OUTPUT_WORKERS:-2}" in text
    env = (COMPOSE / ".env.example").read_text(encoding="utf-8")
    # engine-resource-autotune.sh owns these three by default. A commented
    # line is the documented operator override: uncommenting pins a value that
    # autotune must not overwrite. The compose fallback defaults stay as-is.
    assert re.search(r"^#SECURITY_ENGINE_WEB_CONCURRENCY=1$", env, re.M)
    assert re.search(r"^#SECURITY_INPUT_WORKERS=2$", env, re.M)
    assert re.search(r"^SECURITY_OUTPUT_WORKERS=2$", env, re.M)
    for entry in ("deploy-offline.sh", "upgrade.sh", "upgrade-bundle.sh"):
        assert "engine-resource-autotune.sh" in (COMPOSE / entry).read_text(encoding="utf-8"), entry


ENGINE_TUNABLES = (
    "SECURITY_BATCH_ITEM_CONCURRENCY",
    "SECURITY_CUSTOM_REGEX_RULE_SECONDS",
    "SECURITY_CUSTOM_REGEX_PACK_SECONDS",
    "SECURITY_CUSTOM_REGEX_RULE_MAX_SECONDS",
    "SECURITY_CUSTOM_REGEX_PACK_MAX_SECONDS",
    "SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS",
    "SECURITY_CATALOG_BUDGET_SECONDS",
    "SECURITY_CATALOG_REGEX_TIMEOUT_SECONDS",
    "SECURITY_REGEX_WALL_SLACK",
    "SECURITY_REGEX_WALL_MAX_SECONDS",
)


def _service_block(text, service):
    match = re.search(r"^  %s:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)" % re.escape(service), text, re.M | re.S)
    assert match, service
    return match.group(1)


def test_engine_tunables_pass_through_both_composes():
    # 引擎服务的 environment 是显式清单：不在清单里的变量写进 .env 也不会进容器。
    # 空值透传时代码回落默认，所以统一用 ${VAR:-}，默认值只在代码里维护一处。
    for name in ("docker-compose.yml", "docker-compose.offline.yml"):
        block = _service_block(_engine_env(name), "security-engine")
        for var in ENGINE_TUNABLES:
            assert "- %s=${%s:-}" % (var, var) in block, (name, var)


def test_gateway_retry_backoff_passes_through_both_composes():
    for name in ("docker-compose.yml", "docker-compose.offline.yml"):
        block = _service_block(_engine_env(name), "gateway-core")
        assert "- GATEWAY_SECURITY_RETRY_BACKOFF=${GATEWAY_SECURITY_RETRY_BACKOFF:-}" in block, name
