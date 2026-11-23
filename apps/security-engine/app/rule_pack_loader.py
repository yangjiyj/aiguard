"""
P2-1 Layer 4：引擎侧规则包加载器（方案A：规则编译下发 —— 引擎拉取侧）。

control-plane 把租户在策略中心配置的规则编译为「规则包」，引擎在此模块按租户
拉取规则包并加载进 SecurityEngine。引擎保持无状态：规则由 control-plane 编译，
引擎只消费；不直连数据库。

部署模型：单租户私有化部署。一套引擎服务一个租户（SECURITY_TENANT_ID，默认
tenant_default），启动时拉取一次 + 后台周期热更新。多租户按需后续再扩展（YAGNI）。

容错红线：control-plane 不可达 / 返回异常 / 规则包损坏时，加载器只记录告警并保持
引擎既有规则，绝不崩溃、绝不静默清空规则。请求同时携带内部令牌与租户专用
规则包 attestation，二者职责分离。
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Callable, List

import httpx

# 先确保 engine 模块完整初始化，再导入 custom_rules：engine.py 在模块加载时即实例化
# SecurityEngine()，其 __init__ 延迟导入 custom_rules；若反过来先导入 custom_rules，
# 会触发 engine<->custom_rules 循环导入。固定「engine 先于 custom_rules」打破该环。
from app.detectors import engine as _engine  # noqa: F401
from app.runtime_profile import node_id_or_default
from app.custom_rules import (
    CompiledException,
    CompiledRule,
    CustomRuleSet,
    ExceptionSet,
)
from app.file_inspector import (
    normalize_file_policy,
    replace_file_policy,
    snapshot_file_policy,
)
from app.header_compat import INTERNAL_TOKEN_HEADER
from app.policy_bindings import CompiledPolicy, PolicySet

from app.reply_generator import (
    ReplyPolicy,
    default_reply_policy,
    normalize_reply_policy,

)
logger = logging.getLogger(__name__)

# 与 control-plane internal_auth.go 的 InternalAPISecretHeader 保持一致
# 租户上下文头：control-plane resolveInternalTenantID 读取 X-Tenant-ID
TENANT_HEADER = "X-Tenant-ID"
# 节点身份与持有版本头：引擎据此向 control-plane 上报身份与当前版本，做版本握手
NODE_HEADER = "X-Node-ID"
RULEPACK_VERSION_HEADER = "X-RulePack-Version"
RULEPACK_ACTIVE_COUNT_HEADER = "X-RulePack-Active-Count"
RULEPACK_SKIPPED_COUNT_HEADER = "X-RulePack-Skipped-Count"
RULEPACK_POLICY_COUNT_HEADER = "X-RulePack-Policy-Count"
RULEPACK_REFRESH_SECONDS_HEADER = "X-RulePack-Refresh-Seconds"
RULEPACK_ATTESTATION_HEADER = "X-Rule-Pack-Attestation"
# 引擎能力声明：控制面只向声明了对应能力的引擎下发新字段（如 CompiledPolicy.semantic_action）。
# 旧引擎不带此头，控制面按旧格式下发，严格 DTO 不会因未知字段拒收整个规则包。
ENGINE_CAPABILITIES_HEADER = "X-Engine-Capabilities"
ENGINE_CAPABILITIES = ("semantic_action",)
# control-plane 规则包下发接口路径
RULE_PACK_PATH = "/admin/v1/internal/rules/pack"

DEFAULT_REFRESH_SECONDS = 15
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_TENANT_ID = "tenant_default"
MAX_NODE_ID_LENGTH = 128
MAX_REFRESH_SECONDS = 3600
MAX_ATTESTATION_TOKEN_LENGTH = 256
MAX_RULE_PACK_RESPONSE_BYTES = 8 * 1024 * 1024
_ATTESTATION_TOKEN_PATTERN = re.compile(
    rf"^[A-Za-z0-9!#$%&'*+\-.^_`|~]{{1,{MAX_ATTESTATION_TOKEN_LENGTH}}}$"
)


def _validate_attestation_token(value: str) -> str:
    """Accept only bounded RFC 7230 token characters (or an unset token)."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or _ATTESTATION_TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError("rule-pack attestation token is invalid")
    return value


def _safe_log_error(exc: Exception, *secrets: str) -> str:
    """Return bounded, control-free exception text with configured secrets removed."""
    message = str(exc)
    for secret in secrets:
        normalized = str(secret or "")
        if normalized:
            message = message.replace(normalized, "<redacted>")
    message = "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in message
    )
    return message[:512]


def _normalize_node_id(value: str) -> str:
    """Return a bounded, non-empty identity safe for the handshake header.

    A blank value derives hostname#pid (see runtime_profile.node_id_or_default):
    with WEB_CONCURRENCY>1 every worker pulls rules separately, and a shared
    hostname would make them overwrite each other in the pull-status ledger.
    """
    return node_id_or_default(value)[:MAX_NODE_ID_LENGTH]


@dataclass
class RulePackConfig:
    base_url: str
    token: str
    attestation_token: str = field(default="", repr=False)
    tenant_id: str = DEFAULT_TENANT_ID
    node_id: str = ""
    refresh_seconds: int = DEFAULT_REFRESH_SECONDS
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self.node_id = _normalize_node_id(self.node_id)
        self.attestation_token = _validate_attestation_token(
            self.attestation_token
        )

    @property
    def enabled(self) -> bool:
        # 未配置 control-plane 地址 → 加载器禁用（向后兼容：引擎按无自定义规则运行）
        return bool(self.base_url)

    @property
    def effective_refresh_seconds(self) -> int:
        try:
            return min(MAX_REFRESH_SECONDS, max(1, int(self.refresh_seconds)))
        except (TypeError, ValueError):
            return DEFAULT_REFRESH_SECONDS

    @classmethod
    def from_env(cls) -> "RulePackConfig":
        return cls(
            base_url=os.getenv("CONTROL_PLANE_URL", "").strip(),
            # 与 control-plane JJD_INTERNAL_API_SECRET 同名，部署统一配置
            token=os.getenv("JJD_INTERNAL_API_SECRET", "").strip(),
            attestation_token=os.getenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", ""),
            tenant_id=os.getenv("SECURITY_TENANT_ID", DEFAULT_TENANT_ID).strip()
            or DEFAULT_TENANT_ID,
            node_id=os.getenv("SECURITY_NODE_ID", "").strip(),
            refresh_seconds=_int_env("SECURITY_RULE_REFRESH_SECONDS", DEFAULT_REFRESH_SECONDS),
            timeout=_float_env("SECURITY_RULE_FETCH_TIMEOUT", DEFAULT_TIMEOUT_SECONDS),
        )


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


class RulePackValidationError(ValueError):
    """The fetched rule pack cannot safely replace the complete last-good state."""


def _require_pack_object(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise RulePackValidationError("rule pack must be an object")
    return payload


def _has_exact_matching_matcher(rule: CompiledRule) -> bool:
    """Require exactly the matcher that belongs to the declared runtime type."""
    present = {
        "regex": bool(rule.regex),
        "keyword": bool(rule.keywords),
        "field_name": bool(rule.field_names),
    }
    if rule.rule_type not in present or not present[rule.rule_type]:
        return False
    return sum(present.values()) == 1


def parse_rule_pack(payload: dict) -> List[CompiledRule]:
    """把 control-plane 下发的规则包 JSON 反序列化为 CompiledRule 列表。

    任一条结构损坏或 type/matcher 不一致都拒绝整包；部分加载会让界面版本、
    实际规则与审计回执彼此矛盾，因此不再做逐条静默跳过。
    """
    rules: List[CompiledRule] = []
    payload = _require_pack_object(payload)
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise RulePackValidationError("rule pack rules must be an array")
    for item in raw_rules:
        rule_id = item.get("rule_id") if isinstance(item, dict) else None
        if not isinstance(item, dict):
            raise RulePackValidationError("malformed rule in pack")
        try:
            rule = CompiledRule(**item)
        except Exception as exc:  # pydantic.ValidationError / 类型错误等
            raise RulePackValidationError(
                f"malformed rule in pack (rule_id={rule_id})"
            ) from exc
        if not _has_exact_matching_matcher(rule):
            raise RulePackValidationError(
                f"rule matcher does not match rule_type (rule_id={rule.rule_id})"
            )
        rules.append(rule)
    return rules


def parse_file_policy(payload: dict) -> dict:
    payload = _require_pack_object(payload)
    policy = payload.get("file_policy")

    return normalize_file_policy(policy)

def parse_reply_policy(payload: dict) -> ReplyPolicy:
    payload = _require_pack_object(payload)
    raw = payload.get("reply_policy")
    if raw is None:
        return default_reply_policy()
    return normalize_reply_policy(raw)


def parse_exceptions(payload: dict) -> List[CompiledException]:
    """把规则包中的例外（误报豁免）JSON 反序列化为 CompiledException 列表。

    与 parse_rule_pack 同样逐条解析、坏条跳过并告警，避免一条坏例外拖垮整包。
    红线：高危 finding 永不被例外降级在引擎 ExceptionSet.apply 中保证，此处仅做解析。
    """
    exceptions: List[CompiledException] = []
    payload = _require_pack_object(payload)
    raw = payload.get("exceptions")
    if not isinstance(raw, list):
        raise RulePackValidationError("rule pack exceptions must be an array")
    for item in raw:
        exc_id = item.get("exception_id") if isinstance(item, dict) else None
        if not isinstance(item, dict):
            raise RulePackValidationError("malformed exception in pack")
        try:
            exception = CompiledException(**item)
        except Exception as exc:  # pydantic.ValidationError / 类型错误等
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            ) from exc
        if not exception.exception_id.strip() or exception.decision not in {
            "allow",
            "audit",
        }:
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            )
        try:
            exception.expiry_time()
        except ValueError as exc:
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            ) from exc
        if exception.scope_type not in {
            "tenant",
            "project",
            "user",
            "rule",
            "key_v1",
            "actor_department_v1",
        }:
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            )
        if (
            exception.scope_type in {
                "project",
                "user",
                "key_v1",
                "actor_department_v1",
            }
            and not exception.scope_ref.strip()
        ):
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            )
        if exception.scope_type == "rule" and not exception.rule_id.strip():
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            )
        if (
            exception.include_children
            and exception.scope_type != "actor_department_v1"
        ):
            raise RulePackValidationError(
                f"malformed exception in pack (exception_id={exc_id})"
            )
        exceptions.append(exception)
    return exceptions


def parse_policies(payload: dict) -> List[CompiledPolicy]:
    payload = _require_pack_object(payload)
    raw_policies = payload.get("policies")
    if not isinstance(raw_policies, list):
        raise RulePackValidationError("rule pack policies must be an array")
    policies: List[CompiledPolicy] = []
    for item in raw_policies:
        policy_code = item.get("policy_code") if isinstance(item, dict) else None
        if not isinstance(item, dict):
            raise RulePackValidationError("malformed policy in pack")
        try:
            policies.append(CompiledPolicy.model_validate(item))
        except Exception as exc:
            raise RulePackValidationError(
                f"malformed policy in pack (policy_code={policy_code})"
            ) from exc
    return policies


def _validate_pack_envelope(payload: dict, expected_tenant_id: str) -> None:
    payload = _require_pack_object(payload)
    tenant_id = payload.get("tenant_id")
    if not isinstance(tenant_id, str) or tenant_id != expected_tenant_id:
        raise RulePackValidationError("rule pack tenant_id mismatch")
    version = payload.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RulePackValidationError("rule pack version must be non-empty")
    skipped = payload.get("skipped")
    if not isinstance(skipped, list):
        raise RulePackValidationError("rule pack skipped must be an array")
    for item in skipped:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("rule_id"), str)
            or not isinstance(item.get("reason"), str)
        ):
            raise RulePackValidationError("malformed skipped item in pack")


@dataclass(frozen=True)
class _RulePackCandidate:
    custom_rules: CustomRuleSet
    policies: PolicySet
    exceptions: ExceptionSet
    file_policy: dict
    active_count: int
    skipped_count: int
    policy_count: int
    reply_policy: ReplyPolicy


def _build_candidate(payload: dict, expected_tenant_id: str) -> _RulePackCandidate:
    """Build every runtime component without touching live engine state."""
    _validate_pack_envelope(payload, expected_tenant_id)
    parsed_rules = parse_rule_pack(payload)
    parsed_exceptions = parse_exceptions(payload)
    parsed_policies = parse_policies(payload)
    file_policy = parse_file_policy(payload)
    custom_rules = CustomRuleSet(parsed_rules)
    active_matcher_ids = {
        rule.rule_id for rule, _pattern in custom_rules.active_rules
    }
    for policy in parsed_policies:
        if (
            policy.enabled
            and policy.matcher_rule_id
            and policy.matcher_rule_id not in active_matcher_ids
        ):
            raise RulePackValidationError(
                "enabled policy references an unavailable matcher "
                f"(policy_code={policy.policy_code})"
            )
    policies = PolicySet(parsed_policies)
    exceptions = ExceptionSet(parsed_exceptions)
    reply_policy = parse_reply_policy(payload)
    return _RulePackCandidate(
        custom_rules=custom_rules,
        policies=policies,
        exceptions=exceptions,
        file_policy=file_policy,
        active_count=len(custom_rules.active_rules),
        skipped_count=len(parsed_rules) - len(custom_rules.active_rules),
        policy_count=len(policies),
        reply_policy=reply_policy,
    )


_MISSING = object()


def _restore_attribute(target, name: str, value) -> None:
    if value is _MISSING:
        if hasattr(target, name):
            delattr(target, name)
        return
    setattr(target, name, value)


def _apply_candidate(
    engine,
    candidate: _RulePackCandidate,
    served_version: str,
    on_commit=None,
) -> None:
    """Apply a fully built candidate; rollback every live component on failure."""
    lock = getattr(engine, "_rule_pack_lock", None)
    with lock if lock is not None else nullcontext():
        old_custom_rules = getattr(engine, "custom_rules", _MISSING)
        old_policies = getattr(engine, "policies", _MISSING)
        old_exceptions = getattr(engine, "content_exceptions", _MISSING)
        old_version = getattr(engine, "rule_pack_version", _MISSING)
        old_engine_file_policy = getattr(engine, "file_policy", _MISSING)
        old_file_policy = snapshot_file_policy()
        old_reply_policy = getattr(engine, "reply_policy", _MISSING)
        try:
            engine.load_custom_rules(candidate.custom_rules)
            engine.load_policies(candidate.policies)
            engine.load_file_policy(candidate.file_policy)
            engine.load_content_audit_exceptions(candidate.exceptions)
            engine.rule_pack_version = served_version
            engine.load_reply_policy(candidate.reply_policy)
            if on_commit is not None:
                on_commit()
        except Exception:
            _restore_attribute(engine, "custom_rules", old_custom_rules)
            _restore_attribute(engine, "policies", old_policies)
            _restore_attribute(engine, "content_exceptions", old_exceptions)
            _restore_attribute(engine, "rule_pack_version", old_version)
            _restore_attribute(engine, "file_policy", old_engine_file_policy)
            _restore_attribute(engine, "reply_policy", old_reply_policy)
            replace_file_policy(old_file_policy)
            raise


def _default_client_factory(timeout: float) -> httpx.Client:
    return httpx.Client(timeout=timeout)


class RulePackLoader:
    """按租户从 control-plane 拉取规则包并加载进引擎。

    client_factory 便于测试注入 httpx.MockTransport；生产用默认工厂建真实 Client。
    """

    def __init__(
        self,
        config: RulePackConfig,
        client_factory: Callable[[float], httpx.Client] = _default_client_factory,
    ) -> None:
        self.config = config
        self._client_factory = client_factory
        self._current_version = ""
        self._actual_active_count: int | None = None
        self._actual_skipped_count: int | None = None
        self._actual_policy_count: int | None = None
        # Operational handshake state is one immutable tuple so version/counts are
        # observed as one receipt even if another refresh starts concurrently.
        self._receipt: tuple[str, int | None, int | None, int | None] = (
            "", None, None, None
        )

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def refresh_once(self, engine) -> bool:
        """拉取并加载一次规则包。成功返回 True；任何失败返回 False 且不动引擎现状。"""
        if not self.enabled:
            return False
        try:
            payload = self._fetch()
        except Exception as exc:
            logger.warning(
                "rule-pack fetch failed (%s); keeping current rules",
                _safe_log_error(
                    exc,
                    self.config.attestation_token,
                    self.config.token,
                ),
            )
            return False
        try:
            candidate = _build_candidate(payload, self.config.tenant_id)
            served_version = payload["version"]
            # 同版本仍完成整包离线验证，但不触碰 live 引擎。
            if served_version and served_version == self._receipt[0]:
                return True

            def commit_loader_receipt() -> None:
                self._receipt = (
                    served_version,
                    candidate.active_count,
                    candidate.skipped_count,
                    candidate.policy_count,
                )
                self._actual_active_count = candidate.active_count
                self._actual_skipped_count = candidate.skipped_count
                self._actual_policy_count = candidate.policy_count
                self._current_version = served_version

            _apply_candidate(
                engine,
                candidate,
                served_version,
                on_commit=commit_loader_receipt,
            )
        except Exception as exc:
            logger.warning(
                "rule-pack rejected (%s); keeping complete last-good state", exc
            )
            return False
        logger.info(
            "loaded %d custom rules and %d exceptions for tenant %s",
            candidate.active_count,
            len(candidate.exceptions.exceptions),
            self.config.tenant_id,
        )
        return True

    def refresh_and_acknowledge(self, engine) -> bool:
        """Load one pack and immediately report the newly held receipt.

        The pull endpoint records request headers before serving the pack. A
        second fetch after a successful version change lets the control plane
        observe the version and counts without waiting for another interval.
        Receipt failure never rolls back the already committed last-good pack.
        """
        previous_version = self._receipt[0]
        loaded = self.refresh_once(engine)
        if not loaded or self._receipt[0] == previous_version:
            return loaded
        try:
            self._fetch()
        except Exception as exc:
            logger.warning(
                "rule-pack receipt acknowledgment failed (%s); "
                "keeping newly loaded rules",
                _safe_log_error(
                    exc,
                    self.config.attestation_token,
                    self.config.token,
                ),
            )
        return True

    def _fetch(self) -> dict:
        url = self.config.base_url.rstrip("/") + RULE_PACK_PATH
        # 配置对象可能被热重载方原地修改；发送前再归一化一次，保证永不发空节点头。
        self.config.node_id = _normalize_node_id(self.config.node_id)
        # 配置对象可能被热重载方原地修改；发送前重复验证，绝不把 OWS、CTL、
        # 超长或其它非法 header 字符发给 HTTP 客户端。
        self.config.attestation_token = _validate_attestation_token(
            self.config.attestation_token
        )
        current_version, active_count, skipped_count, policy_count = self._receipt
        headers = {
            INTERNAL_TOKEN_HEADER: self.config.token,
            TENANT_HEADER: self.config.tenant_id,
            NODE_HEADER: self.config.node_id,
            RULEPACK_VERSION_HEADER: current_version,
            RULEPACK_REFRESH_SECONDS_HEADER: str(self.config.effective_refresh_seconds),
            RULEPACK_ATTESTATION_HEADER: self.config.attestation_token,
            ENGINE_CAPABILITIES_HEADER: ",".join(ENGINE_CAPABILITIES),
        }
        if active_count is not None:
            headers[RULEPACK_ACTIVE_COUNT_HEADER] = str(active_count)
        if skipped_count is not None:
            headers[RULEPACK_SKIPPED_COUNT_HEADER] = str(skipped_count)
        if policy_count is not None:
            headers[RULEPACK_POLICY_COUNT_HEADER] = str(policy_count)
        with self._client_factory(self.config.timeout) as client:
            with client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                declared_length = resp.headers.get("Content-Length")
                if declared_length is not None:
                    try:
                        if int(declared_length) > MAX_RULE_PACK_RESPONSE_BYTES:
                            raise RulePackValidationError(
                                "rule pack response exceeds the size limit"
                            )
                    except ValueError:
                        pass

                body = bytearray()
                for chunk in resp.iter_bytes():
                    if len(body) + len(chunk) > MAX_RULE_PACK_RESPONSE_BYTES:
                        raise RulePackValidationError(
                            "rule pack response exceeds the size limit"
                        )
                    body.extend(chunk)
                return json.loads(body)


async def run_refresh_loop(loader: "RulePackLoader", engine, *, sleep=None, run_sync=None) -> None:
    """后台热更新循环：每 refresh_seconds 拉取一次规则包。

    - 被 asyncio 取消时让 CancelledError 向上传播（不吞掉），以便服务优雅关闭。
    - 单次拉取失败由 refresh_once 内部吞掉并保持引擎现状，循环不中断。
    """
    # 用 anyio 而非 asyncio：FastAPI/Starlette 跑在 anyio 上，可兼容 asyncio/trio 后端。
    from anyio import sleep as anyio_sleep, to_thread

    if sleep is None:
        sleep = anyio_sleep
    if run_sync is None:
        run_sync = to_thread.run_sync
    interval = loader.config.effective_refresh_seconds
    while True:
        await sleep(interval)
        # refresh_once 是同步阻塞调用（httpx.Client）；放进线程池执行，避免在引擎
        # 检测热路径上冻结事件循环。refresh_once 内部已吞掉网络/HTTP 异常。
        await run_sync(loader.refresh_and_acknowledge, engine)
