#!/usr/bin/env python3
"""Trusted-development routing rule.

This is a deliberate port of
apps/control-plane/internal/alert/trusted_dev.go, not a second opinion: the
maintenance script has to reach the same verdict the live bridge reaches, for
rows that were written before the rule existed. Both sides are driven from the
same fixtures (deploy/tests/fixtures/trusted_dev/*.json) by
deploy/tests/test_trusted_dev_route.py and internal/alert/trusted_dev_test.go,
so a rule change that only lands on one side fails the other side's tests.

Pure functions only: no database, no environment, no filesystem.
"""

VERSION = "trusted-dev-route-v1"

# Route value written into alert_groups.body_json.triage_route.route.
ROUTE_NAME = "trusted_dev_observation"

# Shipped encoder-agent inventory, overridable with SECEVENT_TRUSTED_DEV_AGENTS.
DEFAULT_AGENTS = (
    "agent_claude_code",
    "agent_openai_codex",
    "agent_workbuddy",
    "agent_cursor",
    "agent_opencode",
    "agent_codebuddy",
    "agent_copilot",
    "agent_cline",
)

# content_source values that describe machine-authored context the coding agent
# read or was handed, rather than something a human typed.
MACHINE_SOURCES = frozenset({"tool_result", "tool_def", "system_prompt"})

# The same thing when the detector only recorded the message role.
MACHINE_ROLES = frozenset({"tool", "system"})

# Evidence classes that keep their actionable disposition wherever observed.
NEVER_ROUTED_TYPES = frozenset({"secret", "data_leak", "file"})

# Event types the bridge dispositions with an earlier return, before this rule
# is ever consulted: tool_execution_risk is forced to action_required and
# tool_attempt_blocked to informational. This rule must agree, or the sweep
# would downgrade a group the live bridge keeps raising as actionable.
BRIDGE_HANDLED_TYPES = frozenset({"tool_execution_risk", "tool_attempt_blocked"})

# A canary in tool output proves a working exfiltration path, not a false
# positive; an illegal-system-command instruction found in a file the agent read
# is exactly the prompt-injection success we must not downgrade.
CANARY_PREFIX = "agent_canary"
INJECTION_CATEGORY = "illegal_system_command_instructions"

ENFORCEMENT_ACTIONS = frozenset({"block", "reply", "deny", "redact", "mask", "rewrite"})
ENFORCEMENT_MARKERS = ("blocked", "replied", "masked", "redacted")

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _text(value):
    return value if isinstance(value, str) else ""


def _key(value):
    return _text(value).strip().lower()


def _findings(event):
    summary = event.get("matched_summary")
    if not isinstance(summary, dict):
        return []
    findings = summary.get("findings")
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def _counts_as_security_finding(finding):
    # Mirrors repository.DominantSecurityFinding: absent means "yes", a string
    # "false" means no, anything unrecognised fails open to "yes".
    if "counts_as_security_finding" not in finding:
        return True
    value = finding["counts_as_security_finding"]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() != "false"
    return True


def _confidence(finding):
    value = finding.get("confidence")
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def dominant_finding(event):
    """Port of repository.DominantSecurityFinding.

    Highest severity wins, tie-broken by fact-ness then confidence then the
    type|category|rule_id|rule_name key, so the choice is deterministic across
    detector order. Findings explicitly marked as non-security evidence cannot
    claim the dominant slot.
    """
    best = None
    best_rank, best_fact, best_conf, best_key = -1, -1, -1.0, ""
    for finding in _findings(event):
        if not _counts_as_security_finding(finding):
            continue
        rank = _SEVERITY_RANK.get(_key(finding.get("severity")), 0)
        confidence = _confidence(finding)
        fact = 0
        if _key(finding.get("type")) == "secret" or finding.get("verified_fact") is True:
            fact = 1
        if _text(finding.get("category")).startswith(CANARY_PREFIX):
            fact = 2
        key = "|".join(str(finding.get(name, "")) for name in ("type", "category", "rule_id", "rule_name"))
        if rank > best_rank or (
            rank == best_rank
            and (fact > best_fact or (fact == best_fact and (confidence > best_conf or (confidence == best_conf and key < best_key))))
        ):
            best, best_rank, best_fact, best_conf, best_key = finding, rank, fact, confidence, key
    return best


def is_enforcement_action(action):
    normalized = _text(action).strip().lower()
    if normalized in ENFORCEMENT_ACTIONS:
        return True
    return any(marker in normalized for marker in ENFORCEMENT_MARKERS)


def has_canary(event):
    return any(_text(finding.get("category")).startswith(CANARY_PREFIX) for finding in _findings(event))


def is_redline(event):
    """Mirrors isRedline: enforcement, canary, type=secret, verified data_leak."""
    if is_enforcement_action(event.get("action_taken")):
        return True
    if has_canary(event):
        return True
    for finding in _findings(event):
        if _text(finding.get("type")) == "secret":
            return True
        if _text(finding.get("type")) == "data_leak":
            if finding.get("verified_fact") is True:
                return True
            if _text(finding.get("content_source")) == "verified_final_output":
                return True
    return False


def _agent_category(event, agents):
    for finding in _findings(event):
        if _key(finding.get("rule_type")) != "agent_detect":
            continue
        category = _key(finding.get("category"))
        if category in agents:
            return category
    summary = event.get("matched_summary")
    if isinstance(summary, dict):
        agent_type = _key(summary.get("agent_type"))
        if agent_type in agents:
            return agent_type
    return ""


def _dominant_routable(dominant):
    if dominant is None:
        return False
    if _key(dominant.get("type")) in NEVER_ROUTED_TYPES:
        return False
    category = _key(dominant.get("category"))
    if category.startswith(CANARY_PREFIX) or category == INJECTION_CATEGORY:
        return False
    return True


def _machine_marker(dominant):
    if dominant is None:
        return ""
    source = _key(dominant.get("content_source"))
    if source in MACHINE_SOURCES:
        return source
    role = _key(dominant.get("message_role"))
    if role in MACHINE_ROLES:
        return role
    return ""


def trusted_development_route(event, agents=None, principals=None):
    """Returns (route, routed).

    route is a dict {"route": ROUTE_NAME, "reason": ...} when routed, {} when
    not. Anything unproven declines, so an unknown event shape keeps asking for
    a human.
    """
    agents = frozenset(_key(agent) for agent in (agents or DEFAULT_AGENTS) if _key(agent))
    principals = frozenset(_text(principal).strip() for principal in (principals or []) if _text(principal).strip())
    if not isinstance(event, dict) or not event:
        return {}, False
    # 0. Event types the bridge dispositions before this rule runs are not ours
    # to re-decide: the sweep and the live path have to reach the same verdict.
    if _key(event.get("event_type")) in BRIDGE_HANDLED_TYPES:
        return {}, False
    # 1. Red lines and enforcement actions always keep the actionable bucket.
    if is_redline(event) or is_enforcement_action(event.get("action_taken")):
        return {}, False
    # 2. The event must prove it came from a coding agent we trust.
    agent_category = _agent_category(event, agents)
    if not agent_category:
        return {}, False
    # 4. The dominant finding must be a class where context explains the hit.
    dominant = dominant_finding(event)
    if not _dominant_routable(dominant):
        return {}, False
    # 3a. Machine context, not something the human wrote.
    marker = _machine_marker(dominant)
    if marker:
        return {"route": ROUTE_NAME, "reason": marker + "_of_" + agent_category}, True
    # 3b. Or the operator explicitly named this principal as trusted.
    principal = _text(event.get("principal_key")).strip()
    if principal and principal in principals:
        return {"route": ROUTE_NAME, "reason": "trusted_principal_of_" + agent_category}, True
    return {}, False
