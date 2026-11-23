"""从 control-plane 的 engine 专属端点拉取完整配置，原子应用并回执。

安全契约：
- 内部共享密钥 + engine 专属 attestation 双重鉴权；
- 托管配置必须完整，任何缺键/非法值都不允许回退 env 后伪报 applied；
- live engine 用不可变候选单指针交换，失败保留 last-good。
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
import urllib.parse

import httpx

from app import feature_flags as ff
from app.header_compat import INTERNAL_TOKEN_HEADER

logger = logging.getLogger(__name__)

ATTESTATION_HEADER = "X-Rule-Pack-Attestation"
TENANT_HEADER = "X-Tenant-ID"
SEMANTIC_CONFIG_PATH = "/admin/v1/internal/security/semantic-config/engine"
SEMANTIC_REPORT_PATH = "/admin/v1/internal/security/semantic-runtime-report/engine"
_REVISION = re.compile(r"^[0-9a-f]{32}$")
_managed_judge_probe_lock = threading.Lock()
_managed_judge_probe_state: dict = {}

_BOOL_KEYS = {
    "inspect_user_input": ff.ENV_INSPECT_USER_INPUT,
    "inspect_model_output": ff.ENV_INSPECT_MODEL_OUTPUT,
    "inspect_builtin_context": ff.ENV_INSPECT_BUILTIN_CONTEXT,
    "inspect_history": ff.ENV_INSPECT_HISTORY,
    "inspect_tool_results": ff.ENV_INSPECT_TOOL_RESULTS,
    "security_audit_only": ff.ENV_AUDIT_ONLY,
    "semantic_enabled": ff.ENV_SEMANTIC_ENABLED,
    "semantic_input_enabled": ff.ENV_SEMANTIC_INPUT_ENABLED,
    "semantic_agent_enabled": ff.ENV_SEMANTIC_AGENT_ENABLED,
    "semantic_output_enabled": ff.ENV_SEMANTIC_OUTPUT_ENABLED,
    "judge_allow_private_egress": ff.ENV_LLM_JUDGE_ALLOW_PRIVATE_EGRESS,
    "tier1_enabled": ff.ENV_TIER1_ENABLED,
    "fp_suppression_enabled": ff.ENV_FP_SUPPRESSION_ENABLED,
    "source_aware_enabled": ff.ENV_SOURCE_AWARE,
    "confidence_gating_enabled": ff.ENV_CONFIDENCE_GATING,
    "coding_traffic_downgrade_enabled": ff.ENV_CODING_TRAFFIC_DOWNGRADE,
    "file_content_dlp_enabled": ff.ENV_FILE_CONTENT_DLP,
}
_STR_KEYS = {
    "judge_backend": ff.ENV_LLM_JUDGE_BACKEND,
    "judge_url": ff.ENV_LLM_JUDGE_URL,
    "judge_model": ff.ENV_LLM_JUDGE_MODEL,
    "judge_api_key": ff.ENV_LLM_JUDGE_API_KEY,
    "tier1_url": ff.ENV_TIER1_URL,
}
_NUM_KEYS = {
    "judge_timeout": ff.ENV_LLM_JUDGE_TIMEOUT,
    "semantic_total_timeout": ff.ENV_SEMANTIC_TOTAL_TIMEOUT,
    "semantic_sample_rate": ff.ENV_SEMANTIC_SAMPLE_RATE,
    "tier1_timeout": ff.ENV_TIER1_TIMEOUT,
    "tier1_low_threshold": ff.ENV_TIER1_LOW_THRESHOLD,
    "tier1_high_threshold": ff.ENV_TIER1_HIGH_THRESHOLD,
    "confidence_threshold": ff.ENV_CONFIDENCE_THRESHOLD,
    "triage_total_budget": ff.ENV_TRIAGE_TOTAL_BUDGET_SECONDS,
}
# 可选数值键：旧 control-plane 不下发时由引擎取默认值（滚动升级兼容）；下发了就必须合法。
_OPTIONAL_NUM_KEYS = {
    "semantic_block_min_confidence": ff.ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE,
}
# 2.9.22 可选键（取值固定集合）：旧 control-plane 不下发时引擎取缺省；下发了就必须合法。
_OPTIONAL_CHOICE_KEYS = {
    "agent_security_monitor_disposition": ff.ENV_AGENT_SECURITY_MONITOR_DISPOSITION,
    "model_output_classified_disposition": ff.ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION,
    "semantic_block_stages": ff.ENV_SEMANTIC_BLOCK_STAGES,
}
_REQUIRED_KEYS = frozenset({
    "revision",
    "judge_backend",
    *_BOOL_KEYS.keys(),
    *_STR_KEYS.keys(),
    *_NUM_KEYS.keys(),
})


def _canonical_managed_config(config: dict) -> bytes:
    chunks: list[bytes] = []
    for name in sorted(key for key in config if key != "revision"):
        value = config[name]
        chunks.append(f"{len(name.encode())}:{name}=".encode())
        if type(value) is bool:
            chunks.append(b"b:1;" if value else b"b:0;")
        elif isinstance(value, str):
            raw = value.encode()
            chunks.extend((f"s:{len(raw)}:".encode(), raw, b";"))
        else:
            raise ValueError(f"semantic managed config {name} has unsupported type")
    return b"".join(chunks)


def _verify_managed_config_attestation(config: dict) -> None:
    key = os.getenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "").strip()
    if len(key) < 16:
        raise ValueError("semantic config attestation key is unavailable")
    mac = hmac.new(
        key.encode(),
        b"jjdguard:semantic-config:security-engine\n" + _canonical_managed_config(config),
        hashlib.sha256,
    ).hexdigest()[:32]
    if not hmac.compare_digest(mac, str(config.get("revision", "")).strip()):
        raise ValueError("semantic config attestation is invalid")


def _validate_url(value: str, *, require_https: bool) -> None:
    if any(ord(char) < 33 for char in str(value)):
        raise ValueError("semantic managed config contains invalid URL")
    try:
        parsed = urllib.parse.urlparse(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("semantic managed config contains invalid URL") from exc
    allowed = {"https"} if require_https else {"http", "https"}
    if (
        parsed.scheme.lower() not in allowed
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("semantic managed config contains invalid URL")


def _validate_managed_config(config: dict) -> None:
    if not isinstance(config, dict):
        raise ValueError("semantic managed config is invalid")
    missing = sorted(
        key
        for key in _REQUIRED_KEYS
        if key not in config
        or config[key] is None
        or (isinstance(config[key], str) and not config[key].strip())
    )
    if missing:
        raise ValueError(
            "incomplete semantic managed config: " + ",".join(missing[:8])
        )

    revision = str(config["revision"]).strip()
    if not _REVISION.fullmatch(revision):
        raise ValueError("semantic config revision is invalid")

    for key in _BOOL_KEYS:
        if type(config[key]) is not bool:  # bool 必须来自 JSON boolean，拒绝字符串/数字歧义
            raise ValueError(f"semantic managed config {key} must be boolean")

    if (
        "security_execution_mode_managed" in config
        and type(config["security_execution_mode_managed"]) is not bool
    ):
        raise ValueError(
            "semantic managed config security_execution_mode_managed must be boolean"
        )

    backend = str(config["judge_backend"]).strip()
    if backend not in {"bundled", "custom", "provider"}:
        raise ValueError("semantic managed config judge_backend is invalid")

    for key in _STR_KEYS:
        value = str(config[key]).strip()
        limit = 8192 if key == "judge_api_key" else (2048 if key.endswith("_url") else 256)
        if not value or len(value) > limit:
            raise ValueError(f"semantic managed config {key} is invalid")

    # 非内置裁判默认必须 TLS；只有显式授权私网出站后才接受明文 HTTP（出站时仍限私网地址）。
    # 内置只允许固定容器服务，不能借 bundled 名义访问任意私网。
    judge_url = str(config["judge_url"]).strip()
    _validate_url(
        judge_url,
        require_https=backend != "bundled" and not config["judge_allow_private_egress"],
    )
    if backend == "bundled":
        parsed_judge = urllib.parse.urlparse(judge_url)
        if not (
            parsed_judge.scheme.lower() == "http"
            and parsed_judge.hostname == "llm-judge"
            and (parsed_judge.port or 80) == 8080
            and parsed_judge.path == "/v1/chat/completions"
            and not parsed_judge.query
            and not parsed_judge.fragment
            and not parsed_judge.username
        ):
            raise ValueError("semantic managed bundled judge URL is invalid")
    _validate_url(str(config["tier1_url"]).strip(), require_https=False)
    if str(config["tier1_url"]).strip() != ff.DEFAULT_TIER1_URL:
        raise ValueError("semantic managed Tier-1 URL must use the bundled sidecar")

    numbers: dict[str, float] = {}
    for key in _NUM_KEYS:
        if not isinstance(config[key], str):
            raise ValueError(f"semantic managed config {key} must be a canonical string")
        try:
            numbers[key] = float(config[key])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"semantic managed config {key} is invalid") from exc
        if not math.isfinite(numbers[key]):
            raise ValueError(f"semantic managed config {key} is invalid")

    for key in (
        "judge_timeout",
        "semantic_total_timeout",
        "tier1_timeout",
        "triage_total_budget",
    ):
        if numbers[key] <= 0 or numbers[key] > 300:
            raise ValueError(f"semantic managed config {key} is out of range")
    for key in (
        "semantic_sample_rate",
        "tier1_low_threshold",
        "tier1_high_threshold",
        "confidence_threshold",
    ):
        if not 0 <= numbers[key] <= 1:
            raise ValueError(f"semantic managed config {key} is out of range")
    if numbers["tier1_low_threshold"] >= numbers["tier1_high_threshold"]:
        raise ValueError("semantic managed config tier1 thresholds are invalid")

    # 引擎键取值必须是字符串（类型不对整份拒绝）；字符串但不认识的取值在验签后由
    # _drop_unknown_engine_options 只忽略该键（与网关一致）。
    for key in _OPTIONAL_CHOICE_KEYS:
        if key in config and not isinstance(config[key], str):
            raise ValueError(f"semantic managed config {key} must be a string")

    if "semantic_block_min_confidence" in config:
        raw = config["semantic_block_min_confidence"]
        if not isinstance(raw, str):
            raise ValueError("semantic managed config semantic_block_min_confidence must be a canonical string")
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("semantic managed config semantic_block_min_confidence is invalid") from exc
        if not math.isfinite(value) or not 0.5 <= value <= 1:
            raise ValueError("semantic managed config semantic_block_min_confidence is out of range")


_ENGINE_OPTION_VALID = {
    "agent_security_monitor_disposition": lambda value: value in ff.OBSERVATION_DISPOSITIONS,
    "model_output_classified_disposition": lambda value: value in ff.OBSERVATION_DISPOSITIONS,
    "semantic_block_stages": lambda value: ff.parse_semantic_block_stages(value) is not None,
}
# 上次忽略的取值（键 → 值），日志只在值变化时打。
_IGNORED_ENGINE_OPTION_VALUES: dict[str, str] = {}


def _drop_unknown_engine_options(config: dict) -> dict:
    """签名里某个引擎键的取值不认识时，只把该键当未下发（取引擎缺省）并记日志，其余照常生效。

    与网关处理不认识的运行时选项取值同口径；必须在验签之后调用（签名覆盖原始取值）。
    """
    kept = dict(config)
    for key, valid in _ENGINE_OPTION_VALID.items():
        if key not in config or valid(config[key]):
            _IGNORED_ENGINE_OPTION_VALUES.pop(key, None)
            continue
        kept.pop(key)
        value = str(config[key])
        if _IGNORED_ENGINE_OPTION_VALUES.get(key) != value:
            _IGNORED_ENGINE_OPTION_VALUES[key] = value
            logger.warning("semantic managed config %s=%r is not recognized; using engine default", key, value[:64])
    return kept


def _deployment_audit_only() -> bool:
    return os.getenv(ff.ENV_AUDIT_ONLY, "").strip().lower() in {"1", "true", "yes", "on"}


def _effective_managed_config(cfg: dict) -> dict:
    """签名下发的托管配置；部署变量 SECURITY_AUDIT_ONLY 只作初值（2.9.22 设计 D7）。

    与网关 semantic_runtime_client 同口径：投影带 security_execution_mode_managed=true
    （控制台显式选过执行模式）时原样生效；没有显式模式时，引擎自己容器的
    SECURITY_AUDIT_ONLY=true 作初值，按只审计执行并重新签出本地生效修订号。
    托管配置拉不到时引擎仍以环境变量启动（见 _enter_safe_record_mode_without_last_good）。
    """
    effective = dict(cfg)
    if (cfg.get("security_execution_mode_managed") is not True
            and cfg.get("security_audit_only") is not True and _deployment_audit_only()):
        effective["security_audit_only"] = True
        key = os.getenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "").strip()
        effective["revision"] = hmac.new(
            key.encode(),
            b"jjdguard:semantic-config:security-engine\n" + _canonical_managed_config(effective),
            hashlib.sha256,
        ).hexdigest()[:32]
    return effective


def map_config_to_overrides(cfg: dict) -> dict[str, str]:
    """把实际有效投影映射成 feature flag override。"""
    overrides: dict[str, str] = {}
    for key, env_name in _BOOL_KEYS.items():
        if key in cfg and cfg[key] is not None:
            value = cfg[key]
            overrides[env_name] = (
                "true"
                if value is True or str(value).lower() in {"1", "true", "yes", "on"}
                else "false"
            )
    for key, env_name in {**_STR_KEYS, **_NUM_KEYS, **_OPTIONAL_NUM_KEYS, **_OPTIONAL_CHOICE_KEYS}.items():
        value = cfg.get(key)
        if value is not None and str(value).strip() != "":
            overrides[env_name] = str(value)
    return overrides


def _reconfigure_live_engine(revision: str) -> None:
    try:
        from app.detectors.engine import engine

        engine.reconfigure_semantic(revision=revision)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "语义配置热重配失败，保留上次运行态：%s", type(exc).__name__
        )
        raise RuntimeError("semantic live reconfigure failed") from exc


def _judge_required(config: dict) -> bool:
    return bool(config["semantic_enabled"]) and any(
        bool(config[key])
        for key in (
            "semantic_input_enabled",
            "semantic_agent_enabled",
            "semantic_output_enabled",
        )
    )


def _managed_judge_readiness(health: dict) -> dict:
    if _managed_judge_probe_state.get("pair_ready") is not True:
        return dict(health, operational=False)
    if _managed_judge_probe_state.get("ready_once") is not True:
        # 签名变化后的首次就绪：不再要求窗口内零失败（负载导致的零星超时会让控制台
        # 永远显示不可用）。条件：health 本身 operational（成功率 >= 下限、熔断未开），
        # 且样本数 >= 最小样本数；样本不足时只有"零失败"才算就绪，避免误报健康，
        # 同时保持空闲系统（仅探针 2 次成功）原有行为。
        from app.detectors.llm_judge import SEMANTIC_JUDGE_MIN_WINDOW_ATTEMPTS
        attempts = int(health.get("window_attempts", 0))
        successes = int(health.get("window_successes", 0))
        enough = attempts >= SEMANTIC_JUDGE_MIN_WINDOW_ATTEMPTS
        if not health.get("operational") or (not enough and attempts > successes):
            return dict(health, operational=False)
        _managed_judge_probe_state["ready_once"] = True
    return health


def _probe_managed_judge(config: dict) -> dict:
    from app.detectors.llm_judge import (get_semantic_judge_health, judge_semantic,
        judge_capacity_skipped, semantic_judge_health_identity, has_recent_semantic_judge_success)

    url = str(config["judge_url"]).strip()
    options = dict(url=url, model=str(config["judge_model"]).strip(),
                   api_key=str(config["judge_api_key"]),
                   timeout=max(0.1, float(config["judge_timeout"])),
                   judge_backend=str(config["judge_backend"]).strip(),
                   allow_private_egress=bool(config["judge_allow_private_egress"]))
    identity = semantic_judge_health_identity(**options)
    signature = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":"),
                                           allow_nan=False).encode()).hexdigest()
    with _managed_judge_probe_lock:
        same = _managed_judge_probe_state.get("configuration") == signature
        if not same:
            _managed_judge_probe_state.update(configuration=signature, pair_ready=False, ready_once=False)
        if (same and _managed_judge_probe_state.get("pair_ready") is True
                and has_recent_semantic_judge_success(url, identity=identity)):
            return _managed_judge_readiness(get_semantic_judge_health(url, identity=identity))

        # Establish the advertised two-request capacity before reporting readiness.
        # Every call retains the configured deadline and the production request contract.
        workers = 2 if config["judge_backend"] == "bundled" else 1
        barrier = threading.Barrier(workers)
        def probe():
            barrier.wait(timeout=5)
            opinion = judge_semantic(
                "JJDGuard semantic runtime health check. Treat this sentence as benign.",
                **options)
            return bool(opinion is not None and opinion.verdict == "benign"
                        and opinion.category == "none" and not judge_capacity_skipped())
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(probe) for _ in range(workers)]
            completed = [future.result() for future in futures]
        pair_ready = all(completed)
        _managed_judge_probe_state.update(configuration=signature, pair_ready=pair_ready)
        health = get_semantic_judge_health(url, identity=identity)
        return _managed_judge_readiness(health)


def _runtime_node_id() -> str:
    value = (
        os.getenv("SEMANTIC_RUNTIME_NODE_ID", "").strip()
        or os.getenv("HOSTNAME", "").strip()
        or "security-engine"
    )
    # 多 worker（uvicorn --workers / WEB_CONCURRENCY>1）时每个进程各自上报；
    # 控制面按 component+node_id 归档，同名会互相覆盖，故追加进程后缀。单进程保持原值。
    try:
        multi_worker = int(os.getenv("WEB_CONCURRENCY", "").strip() or "1") > 1
    except ValueError:
        multi_worker = False
    if multi_worker:
        suffix = "#%d" % os.getpid()
        return value[:128 - len(suffix)] + suffix
    return value[:128]


def _auth_headers(token: str) -> dict[str, str]:
    attestation = os.getenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "").strip()
    if not token or not attestation:
        raise RuntimeError("semantic engine authentication is not configured")
    return {
        INTERNAL_TOKEN_HEADER: token,
        ATTESTATION_HEADER: attestation,
        TENANT_HEADER: "tenant_default",
    }


def _report_runtime(
    base_url: str,
    token: str,
    timeout: float,
    *,
    applied_revision: str = "",
    error_code: str = "",
    held_revision: str = "",
    config_loaded: bool = False,
    judge_required: bool = False,
    judge_operational: bool = False,
    judge_consecutive_failures: int = 0,
    judge_breaker_open: bool = False,
    judge_last_attempt_at: str = "",
    judge_last_success_at: str = "",
    judge_window_attempts: int = 0,
    judge_window_successes: int = 0,
    judge_window_timeouts: int = 0,
    judge_p50_latency_ms: float = 0.0,
) -> None:
    payload = {
        "component": "security-engine",
        "node_id": _runtime_node_id(),
        "config_loaded": bool(config_loaded),
        "judge_required": bool(judge_required),
        "judge_operational": bool(judge_operational),
        "judge_consecutive_failures": max(0, int(judge_consecutive_failures)),
        "judge_breaker_open": bool(judge_breaker_open),
        "judge_window_attempts": max(0, int(judge_window_attempts)),
        "judge_window_successes": max(0, int(judge_window_successes)),
        "judge_window_timeouts": max(0, int(judge_window_timeouts)),
        "judge_p50_latency_ms": max(0.0, float(judge_p50_latency_ms)),
    }
    if applied_revision:
        payload["applied_revision"] = applied_revision
    if error_code:
        payload["error_code"] = error_code
    if held_revision:
        payload["held_revision"] = held_revision
    if judge_last_attempt_at:
        payload["judge_last_attempt_at"] = str(judge_last_attempt_at)
    if judge_last_success_at:
        payload["judge_last_success_at"] = str(judge_last_success_at)
    response = httpx.post(
        base_url.rstrip("/") + SEMANTIC_REPORT_PATH,
        headers=_auth_headers(token),
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()


def _held_revision() -> str:
    try:
        from app.detectors.engine import engine

        held = str(engine.semantic_config_revision).strip()
        return held if _REVISION.fullmatch(held) else ""
    except Exception:  # noqa: BLE001
        return ""


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, ValueError):
        return "config_invalid"
    if isinstance(exc, RuntimeError):
        return "apply_failed"
    if isinstance(exc, httpx.HTTPError):
        return "control_plane_unavailable"
    return "refresh_failed"


def _fetch_once(base_url: str, token: str, timeout: float) -> str:
    response = httpx.get(
        base_url.rstrip("/") + SEMANTIC_CONFIG_PATH,
        headers=_auth_headers(token),
        timeout=timeout,
    )
    response.raise_for_status()
    config = response.json()
    _validate_managed_config(config)
    _verify_managed_config_attestation(config)
    config = _drop_unknown_engine_options(_effective_managed_config(config))
    revision = str(config["revision"]).strip()

    overrides = map_config_to_overrides(config)
    previous_overrides = ff.snapshot_overrides()
    # A heartbeat with the same effective configuration must not replace the
    # detector and discard completed-window caches during a bounded recovery.
    # Changed values still reconfigure even if a sender reused the revision.
    if previous_overrides != overrides or _held_revision() != revision:
        ff.apply_overrides(overrides)
        try:
            _reconfigure_live_engine(revision)
        except Exception:
            ff.apply_overrides(previous_overrides)
            raise

    judge_required = _judge_required(config)
    judge_health = {
        "operational": False,
        "consecutive_failures": 0,
        "breaker_open": False,
        "last_attempt_at": "",
        "last_success_at": "",
        "window_attempts": 0,
        "window_successes": 0,
        "window_timeouts": 0,
        "p50_latency_ms": 0.0,
    }
    if judge_required:
        judge_health = _probe_managed_judge(config)
    judge_operational = bool(judge_health.get("operational")) if judge_required else False
    _report_runtime(
        base_url,
        token,
        timeout,
        applied_revision=revision,
        error_code="" if not judge_required or judge_operational else "judge_unavailable",
        config_loaded=True,
        judge_required=judge_required,
        judge_operational=judge_operational,
        judge_consecutive_failures=int(judge_health.get("consecutive_failures", 0)),
        judge_breaker_open=bool(judge_health.get("breaker_open")),
        judge_last_attempt_at=str(judge_health.get("last_attempt_at", "")),
        judge_last_success_at=str(judge_health.get("last_success_at", "")),
        judge_window_attempts=int(judge_health.get("window_attempts", 0)),
        judge_window_successes=int(judge_health.get("window_successes", 0)),
        judge_window_timeouts=int(judge_health.get("window_timeouts", 0)),
        judge_p50_latency_ms=float(judge_health.get("p50_latency_ms", 0.0)),
    )
    return revision


def _enter_safe_record_mode_without_last_good() -> None:
    if _held_revision():
        return
    previous_overrides = ff.snapshot_overrides()
    safe_overrides = dict(previous_overrides)
    safe_overrides[ff.ENV_AUDIT_ONLY] = "true"
    ff.apply_overrides(safe_overrides)
    try:
        _reconfigure_live_engine(None)
    except Exception:
        ff.apply_overrides(previous_overrides)
        raise


def start(refresh_seconds: int = 60) -> None:
    base_url = os.getenv("CONTROL_PLANE_URL", "").strip()
    token = os.getenv("JJD_INTERNAL_API_SECRET", "").strip()
    if not base_url:
        logger.info("CONTROL_PLANE_URL 未配置，语义配置走 env（不热读）")
        return
    refresh_seconds = max(5, min(int(refresh_seconds), 3600))

    def refresh() -> None:
        try:
            _fetch_once(base_url, token, 5.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "语义配置热读失败，保留上次运行态：%s", type(exc).__name__
            )
            if not _held_revision():
                try:
                    _enter_safe_record_mode_without_last_good()
                except Exception as safe_exc:  # noqa: BLE001
                    logger.warning(
                        "首次热读失败后的安全 record 初始化失败：%s",
                        type(safe_exc).__name__,
                    )
            try:
                _report_runtime(
                    base_url,
                    token,
                    5.0,
                    error_code=_failure_code(exc),
                    held_revision=_held_revision(),
                    config_loaded=bool(_held_revision()),
                    judge_required=False,
                    judge_operational=False,
                )
            except Exception as report_exc:  # noqa: BLE001
                logger.warning(
                    "语义运行失败回执未送达：%s", type(report_exc).__name__
                )

    refresh()

    def loop() -> None:
        while True:
            time.sleep(refresh_seconds)
            refresh()

    threading.Thread(
        target=loop, daemon=True, name="semantic-config-loader"
    ).start()
