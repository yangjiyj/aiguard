"""Startup guard that proves the current runtime policy mode is effective."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.detectors.engine import SecurityEngine, SecurityFinding


class StartupSelfCheckError(RuntimeError):
    """Raised when detection actions disagree with the runtime policy mode."""


@dataclass(frozen=True)
class _Probe:
    name: str
    run: Callable[[SecurityEngine], str]
    expected_action: str


def assert_runtime_policy_consistency(engine: SecurityEngine) -> None:
    """Fail startup unless ordinary paths honor the current runtime snapshot.

    ``SECURITY_AUDIT_ONLY`` is only the safe boot fallback. The control-plane
    managed config may atomically replace it with strict mode, so startup must
    not turn the environment value into a permanent invariant. These probes
    prove two invariants: unbound built-in capabilities remain audit-only, while
    an explicitly configured block policy follows the immutable runtime mode.
    Deterministic redline probes are excluded because they exercise a separate
    detector contract rather than runtime-snapshot propagation.
    """
    errors: list[str] = []
    runtime = engine.snapshot_semantic_runtime()
    configured_action = "audit" if runtime.audit_only else "block"

    probes = (
        _Probe(
            "unbound_check_input",
            lambda eng: eng.check_input(
                "startup-selfcheck-input",
                "api_key=ordinaryvalue123456",  # pragma: allowlist secret nosemgrep
            ).action,
            "audit",
        ),
        _Probe(
            "unbound_check_output",
            lambda eng: eng.check_output(
                "startup-selfcheck-output",
                "身份证号码: 11010519491231002X",  # pragma: allowlist secret nosemgrep
            ).action,
            "audit",
        ),
        _Probe(
            "configured_policy",
            lambda eng: eng._determine_action([
                SecurityFinding(
                    type="secret",
                    category="startup_probe",
                    severity="critical",
                    matched_text_preview="<MASKED>",
                    rule_id="policy.startup.probe",
                    policy_code="startup.probe",
                    action="block",
                    confidence=1.0,
                )
            ], runtime),
            configured_action,
        ),
    )
    for probe in probes:
        try:
            action = probe.run(engine)
        except Exception as exc:  # pragma: no cover - defensive startup detail
            errors.append(f"{probe.name} probe raised {exc.__class__.__name__}: {exc}")
            continue
        if action != probe.expected_action:
            errors.append(
                f"{probe.name} expected action={probe.expected_action}, got {action}"
            )

    if errors:
        raise StartupSelfCheckError("; ".join(errors))


def assert_production_audit_only(engine: SecurityEngine) -> None:
    """Backward-compatible name for the runtime policy consistency check."""
    assert_runtime_policy_consistency(engine)


def assert_deployment_coordination() -> dict:
    """Prove the multi-worker deployment can actually coordinate.

    Fails startup only for an unambiguous misconfiguration: the deployment
    declares shared state required but no URL was installed. A live valkey
    outage is handled at runtime by the documented fail-closed/audited
    degradations instead of taking the whole gateway down at boot.
    """
    import logging
    import os
    from app.runtime_profile import cascade_warnings, resource_profile
    from app.shared_state import get_shared_state

    logger = logging.getLogger(__name__)
    state = get_shared_state()
    required = state.required
    mode = state.mode
    if required and mode == "local":
        raise StartupSelfCheckError(
            "SECURITY_SHARED_STATE_REQUIRED=true but SECURITY_SHARED_STATE_URL is unset; "
            "multi-worker state would be silently process-local"
        )
    if mode == "valkey":
        try:
            state.ping()
        except Exception as exc:
            logger.error("shared state unreachable at startup: %s", type(exc).__name__)
    profile = resource_profile()
    warnings = cascade_warnings()
    for warning in warnings:
        logger.warning("cascade configuration warning: %s", warning)
    if profile["judge_budget_status"].startswith("over_budget"):
        logger.warning("judge global budget exceeded: %s", profile["judge_budget_status"])
    return {
        "shared_state_mode": mode,
        "shared_state_required": required,
        "resource_profile": profile,
        "cascade_warnings": warnings,
    }
