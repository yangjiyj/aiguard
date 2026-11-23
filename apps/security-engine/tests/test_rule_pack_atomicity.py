"""规则包严格验证与 last-good 原子替换回归测试。"""

from __future__ import annotations

import httpx
import pytest
import threading

from app import file_inspector, rule_pack_loader as rule_pack_loader_module
from app.detectors.engine import SecurityEngine
from app.rule_pack_loader import RulePackConfig, RulePackLoader


def _rule(rule_id: str, regex: str) -> dict:
    return {
        "rule_id": rule_id,
        "rule_name": rule_id,
        "rule_type": "regex",
        "category": "custom",
        "severity": "high",
        "action": "block",
        "enabled": True,
        "regex": regex,
    }


def _pack(
    version: str,
    rule_id: str,
    *,
    blocked_type: str = "pdf",
    include_bad_python_regex: bool = False,
) -> dict:
    rules = [_rule(rule_id, rf"{rule_id}-[0-9]+")]
    if include_bad_python_regex:
        rules.append(_rule(f"{rule_id}_bad_python", "("))
    return {
        "tenant_id": "tenant_default",
        "version": version,
        "rules": rules,
        "policies": [
            {
                "policy_code": f"policy.{rule_id}",
                "policy_id": f"policy_id_{rule_id}",
                "policy_name": f"policy {rule_id}",
                "policy_type": "matcher_policy",
                "scene": "prompt_injection",
                "matcher_rule_id": rule_id,
                "action": "block",
                "enabled": True,
                "binding_mode": "any",
                "capabilities": [],
            }
        ],
        "exceptions": [
            {
                "exception_id": f"exc_{rule_id}",
                "scope_type": "rule",
                "rule_id": rule_id,
                "decision": "audit",
            }
        ],
        "skipped": [],
        "file_policy": {
            "blocked_types": [blocked_type],
            "max_file_mb": 20,
            "max_zip_ratio": 100,
            "max_attachments": 10,
        },
    }


def _loader(current: dict) -> RulePackLoader:
    def handler(_request: httpx.Request) -> httpx.Response:
        if "response" in current:
            return current["response"]
        return httpx.Response(200, json=current["pack"])

    def factory(timeout: float) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    return RulePackLoader(
        RulePackConfig(
            base_url="http://control-plane.local",
            token="internal-secret",
            tenant_id="tenant_default",
        ),
        client_factory=factory,
    )


def _state(engine: SecurityEngine, loader: RulePackLoader) -> tuple:
    active_rule_ids = tuple(
        rule.rule_id for rule, _pattern in engine.custom_rules.active_rules
    )
    policy_codes = tuple(policy.policy_code for policy in engine.policies.policies)
    exception_ids = tuple(
        exc.exception_id for exc in engine.content_exceptions.exceptions
    )
    return (
        active_rule_ids,
        policy_codes,
        exception_ids,
        file_inspector.snapshot_file_policy(),
        engine.rule_pack_version,
        loader._current_version,
        loader._actual_active_count,
        loader._actual_skipped_count,
        loader._actual_policy_count,
        loader._receipt,
    )


@pytest.fixture(autouse=True)
def restore_global_file_policy():
    old_policy = file_inspector.snapshot_file_policy()
    try:
        yield
    finally:
        file_inspector.load_file_policy(old_policy)


def _load_old_state() -> tuple[dict, RulePackLoader, SecurityEngine, tuple]:
    current = {"pack": _pack("version-old", "old_rule")}
    loader = _loader(current)
    engine = SecurityEngine()
    assert loader.refresh_once(engine) is True
    return current, loader, engine, _state(engine, loader)


def test_malformed_rule_rejects_entire_pack_and_preserves_last_good():
    current, loader, engine, old_state = _load_old_state()
    malformed = _pack("version-new", "new_rule")
    malformed["rules"].append({"rule_id": "broken"})
    current["pack"] = malformed

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enabled", "false"),
        ("unexpected_runtime_switch", True),
    ],
)
def test_non_strict_rule_payload_rejects_entire_pack_and_preserves_last_good(
    field, value,
):
    current, loader, engine, old_state = _load_old_state()
    candidate = _pack("version-new", "new_rule")
    candidate["rules"][0][field] = value
    current["pack"] = candidate

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_enabled_policy_with_missing_matcher_rejects_pack_and_preserves_last_good():
    current, loader, engine, old_state = _load_old_state()
    candidate = _pack("version-new", "new_rule")
    candidate["policies"][0]["matcher_rule_id"] = "missing_rule"
    current["pack"] = candidate

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_disabled_policy_may_retain_missing_matcher_reference():
    current = {"pack": _pack("version-disabled", "new_rule")}
    current["pack"]["policies"][0]["enabled"] = False
    current["pack"]["policies"][0]["matcher_rule_id"] = "missing_rule"
    loader = _loader(current)
    engine = SecurityEngine()

    assert loader.refresh_once(engine) is True
    assert [policy.policy_code for policy in engine.policies.policies] == [
        "policy.new_rule"
    ]


@pytest.mark.parametrize("invalid_action", ["reply", "alert", "quarantine", "blok"])
def test_unsupported_rule_action_rejects_pack_and_preserves_last_good(
    invalid_action,
):
    current, loader, engine, old_state = _load_old_state()
    candidate = _pack("version-new", "new_rule")
    candidate["rules"][0]["action"] = invalid_action
    current["pack"] = candidate

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_oversized_http_response_preserves_last_good(monkeypatch):
    current, loader, engine, old_state = _load_old_state()
    monkeypatch.setattr(rule_pack_loader_module, "MAX_RULE_PACK_RESPONSE_BYTES", 256)
    current["response"] = httpx.Response(
        200,
        content=b'{"exceptions":"' + b"x" * 512 + b'"}',
    )

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_malformed_file_policy_rejects_entire_pack_and_preserves_last_good():
    current, loader, engine, old_state = _load_old_state()
    malformed = _pack("version-new", "new_rule")
    malformed["file_policy"]["blocked_types"] = "png"
    current["pack"] = malformed

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


@pytest.mark.parametrize(
    "invalid_exception",
    [
        {
            "exception_id": "exc_typo_scope",
            "scope_type": "projcet",
            "scope_ref": "project-a",
            "decision": "allow",
        },
        {
            "exception_id": "exc_extra_field",
            "scope_type": "project",
            "scope_ref": "project-a",
            "decision": "allow",
            "unexpected_project": "project-b",
        },
        {
            "exception_id": "exc_project_without_ref",
            "scope_type": "project",
            "scope_ref": "",
            "decision": "allow",
        },
        {
            "exception_id": "exc_user_without_ref",
            "scope_type": "user",
            "decision": "allow",
        },
        {
            "exception_id": "exc_rule_without_id",
            "scope_type": "rule",
            "decision": "allow",
        },
    ],
)
def test_malicious_exception_scope_rejects_pack_and_preserves_last_good(
    invalid_exception,
):
    current, loader, engine, old_state = _load_old_state()
    candidate = _pack("version-new", "new_rule")
    candidate["exceptions"] = [invalid_exception]
    current["pack"] = candidate

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-other"),
        ("version", ""),
        ("version", "   "),
    ],
)
def test_envelope_mismatch_or_blank_version_preserves_last_good(field, value):
    current, loader, engine, old_state = _load_old_state()
    candidate = _pack("version-new", "new_rule")
    candidate[field] = value
    current["pack"] = candidate

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_file_policy_apply_error_rolls_back_rules_policy_version_and_counts(
    monkeypatch,
):
    current, loader, engine, old_state = _load_old_state()
    current["pack"] = _pack(
        "version-new",
        "new_rule",
        blocked_type="png",
        include_bad_python_regex=True,
    )
    original_apply = engine.load_file_policy

    def fail_after_file_policy_mutation(policy):
        original_apply(policy)
        raise RuntimeError("file policy apply failed")

    monkeypatch.setattr(engine, "load_file_policy", fail_after_file_policy_mutation)

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_exception_apply_error_rolls_back_rules_policy_version_and_counts(
    monkeypatch,
):
    current, loader, engine, old_state = _load_old_state()
    current["pack"] = _pack(
        "version-new",
        "new_rule",
        blocked_type="png",
        include_bad_python_regex=True,
    )
    original_apply = engine.load_content_audit_exceptions

    def fail_after_exception_mutation(exceptions):
        original_apply(exceptions)
        raise RuntimeError("exception apply failed")

    monkeypatch.setattr(
        engine, "load_content_audit_exceptions", fail_after_exception_mutation
    )

    assert loader.refresh_once(engine) is False
    assert _state(engine, loader) == old_state


def test_concurrent_reader_never_observes_mixed_runtime_pack(monkeypatch):
    current, loader, engine, _old_state = _load_old_state()
    current["pack"] = _pack(
        "version-new",
        "new_rule",
        blocked_type="png",
        include_bad_python_regex=True,
    )

    writer_inside_apply = threading.Event()
    release_writer = threading.Event()
    reader_started = threading.Event()
    reader_done = threading.Event()
    writer_result = []
    reader_result = []
    reader_errors = []
    original_load_file_policy = engine.load_file_policy

    def pause_between_component_updates(policy):
        writer_inside_apply.set()
        if not release_writer.wait(timeout=2):
            raise RuntimeError("test did not release writer")
        original_load_file_policy(policy)

    monkeypatch.setattr(engine, "load_file_policy", pause_between_component_updates)

    writer = threading.Thread(
        target=lambda: writer_result.append(loader.refresh_once(engine)),
        daemon=True,
    )
    writer.start()
    assert writer_inside_apply.wait(timeout=2)

    def read_snapshot():
        reader_started.set()
        try:
            reader_result.append(engine.snapshot_rule_pack_state())
        except Exception as exc:  # exposed as a deterministic test failure below
            reader_errors.append(exc)
        finally:
            reader_done.set()

    reader = threading.Thread(target=read_snapshot, daemon=True)
    reader.start()
    assert reader_started.wait(timeout=2)
    try:
        assert not reader_done.wait(timeout=0.1), (
            "reader escaped while the writer held a partially applied pack"
        )
    finally:
        release_writer.set()

    writer.join(timeout=2)
    reader.join(timeout=2)
    assert not writer.is_alive() and not reader.is_alive()
    assert writer_result == [True]
    assert reader_errors == []
    assert len(reader_result) == 1

    custom_rules, policies, exceptions, file_policy, reply_policy, version = reader_result[0]
    assert [rule.rule_id for rule, _pattern in custom_rules.active_rules] == [
        "new_rule"
    ]
    assert [rule.rule_id for rule in custom_rules.skipped] == [
        "new_rule_bad_python"
    ]
    assert [policy.policy_code for policy in policies.policies] == [
        "policy.new_rule"
    ]
    assert [exc.exception_id for exc in exceptions.exceptions] == ["exc_new_rule"]
    assert file_policy["blocked_types"] == ["png"]
    assert version == "version-new"
    assert loader._actual_active_count == 1
    assert reply_policy.enabled is False
    assert loader._actual_skipped_count == 1
    assert loader._actual_policy_count == 1
    assert loader._receipt == ("version-new", 1, 1, 1)


def test_python_regex_compile_failure_is_successful_degraded_load():
    current = {
        "pack": _pack(
            "version-degraded",
            "valid_rule",
            include_bad_python_regex=True,
        )
    }
    loader = _loader(current)
    engine = SecurityEngine()

    assert loader.refresh_once(engine) is True
    assert [
        rule.rule_id for rule, _pattern in engine.custom_rules.active_rules
    ] == ["valid_rule"]
    assert [rule.rule_id for rule in engine.custom_rules.skipped] == [
        "valid_rule_bad_python"
    ]
    assert engine.rule_pack_version == "version-degraded"
    assert loader._actual_active_count == 1
    assert loader._actual_skipped_count == 1


def test_missing_file_policy_apply_capability_rejects_candidate_without_mutation():
    current = {"pack": _pack("version-new", "new_rule")}
    loader = _loader(current)

    class EngineWithoutFilePolicyApply:
        def __init__(self):
            self.custom_rules = object()
            self.policies = object()
            self.content_exceptions = object()
            self.rule_pack_version = "version-old"

        def load_custom_rules(self, rules):
            self.custom_rules = rules

        def load_policies(self, policies):
            self.policies = policies

        def load_content_audit_exceptions(self, exceptions):
            self.content_exceptions = exceptions

    engine = EngineWithoutFilePolicyApply()
    old_state = (
        engine.custom_rules,
        engine.policies,
        engine.content_exceptions,
        engine.rule_pack_version,
        loader._current_version,
        loader._actual_active_count,
        loader._actual_skipped_count,
        loader._actual_policy_count,
        loader._receipt,
    )

    assert loader.refresh_once(engine) is False
    assert (
        engine.custom_rules,
        engine.policies,
        engine.content_exceptions,
        engine.rule_pack_version,
        loader._current_version,
        loader._actual_active_count,
        loader._actual_skipped_count,
        loader._actual_policy_count,
        loader._receipt,
    ) == old_state
