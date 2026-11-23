"""Cross-language check for the trusted-development routing rule and its sweep.

Every routing case comes from deploy/tests/fixtures/trusted_dev/*.json, the same
files driven by apps/control-plane/internal/alert/trusted_dev_test.go. If the Go
rule and this port drift apart, one of the two suites goes red.

The maintenance-template tests guard the sweep's guest payload: it is assembled by
string substitution, so a stray placeholder would ship broken code into the VM
without failing anywhere else.
"""
import ast
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "deploy", "maintenance"))

from trusted_dev_route import (  # noqa: E402
    BRIDGE_HANDLED_TYPES,
    DEFAULT_AGENTS,
    ROUTE_NAME,
    VERSION,
    dominant_finding,
    trusted_development_route,
)

FIXTURE_DIR = os.path.join(HERE, "fixtures", "trusted_dev")


def load_fixtures():
    names = sorted(name for name in os.listdir(FIXTURE_DIR) if name.endswith(".json"))
    fixtures = []
    for name in names:
        with open(os.path.join(FIXTURE_DIR, name), "r", encoding="utf-8") as handle:
            fixtures.append(json.load(handle))
    return fixtures


def route_config(fixture):
    """A fixture only pins the lists it cares about; an absent list keeps the
    shipped default, exactly like the Go fixture helper."""
    config = fixture.get("config") or {}
    agents = config.get("agents")
    if agents is None:
        agents = list(DEFAULT_AGENTS)
    principals = config.get("principals") or []
    return agents, principals


def test_fixture_set_is_present():
    fixtures = load_fixtures()
    assert len(fixtures) >= 10, "shared routing fixtures are missing"
    for fixture in fixtures:
        assert fixture.get("name"), fixture
        assert fixture.get("event", {}).get("matched_summary"), fixture["name"]
        if fixture["expect"]["routed"]:
            assert fixture["expect"]["reason"], fixture["name"]


def test_every_fixture_matches_the_router():
    routed = 0
    declined = 0
    for fixture in load_fixtures():
        agents, principals = route_config(fixture)
        route, hit = trusted_development_route(fixture["event"], agents=agents, principals=principals)
        assert hit is fixture["expect"]["routed"], "%s: routed=%s want %s" % (
            fixture["name"], hit, fixture["expect"]["routed"],
        )
        if not hit:
            assert route == {}, fixture["name"]
            declined += 1
            continue
        assert route["route"] == ROUTE_NAME, fixture["name"]
        assert route["reason"] == fixture["expect"]["reason"], "%s: reason=%r want %r" % (
            fixture["name"], route["reason"], fixture["expect"]["reason"],
        )
        routed += 1
    # Both directions must actually be exercised: an always-decline or
    # always-route implementation has to fail here.
    assert routed > 0 and declined > 0, "routed=%d declined=%d" % (routed, declined)


def test_agent_inventory_override_admits_a_new_client():
    event = {
        "event_type": "prompt_leak_internal_rules",
        "severity": "high",
        "action_taken": "audit",
        "principal_key": "user_1",
        "matched_summary": {
            "agent_type": "agent_acme_cli",
            "findings": [
                {"rule_type": "agent_detect", "category": "agent_acme_cli", "severity": "low", "counts_as_security_finding": False},
                {"category": "prompt_leak_internal_rules", "severity": "high", "counts_as_security_finding": True, "content_source": "tool_result"},
            ],
        },
    }
    route, hit = trusted_development_route(event)
    assert hit is False, "an unknown agent must not route with the shipped inventory"
    route, hit = trusted_development_route(event, agents=["agent_acme_cli"])
    assert hit is True
    assert route["reason"] == "tool_result_of_agent_acme_cli"


def test_principal_is_trimmed_before_matching():
    event = {
        "event_type": "prompt_injection",
        "severity": "high",
        "action_taken": "audit",
        "principal_key": " user_trusted ",
        "matched_summary": {
            "agent_type": "agent_claude_code",
            "findings": [
                {"category": "keyword_classic_injection", "severity": "high", "counts_as_security_finding": True, "content_source": "assistant_history"},
            ],
        },
    }
    assert trusted_development_route(event, principals=[" user_trusted "])[1] is True


def test_dominant_finding_prefers_severity_over_detector_order():
    event = {
        "matched_summary": {
            "findings": [
                {"category": "low_first", "severity": "low", "counts_as_security_finding": True},
                {"category": "critical_second", "severity": "critical", "counts_as_security_finding": True},
            ]
        }
    }
    assert dominant_finding(event)["category"] == "critical_second"


def test_non_security_findings_cannot_claim_the_dominant_slot():
    event = {
        "matched_summary": {
            "findings": [
                {"category": "agent_claude_code", "severity": "critical", "counts_as_security_finding": False},
                {"category": "phone_cn", "severity": "medium", "counts_as_security_finding": True},
            ]
        }
    }
    assert dominant_finding(event)["category"] == "phone_cn"


def test_version_is_reported_for_the_dry_run_output():
    assert VERSION == "trusted-dev-route-v1"


def test_bridge_handled_event_types_are_never_rerouted():
    """computeLifecycleFields dispositions these with an earlier return, before the
    rule is consulted. A sweep that ignored that would downgrade a group the live
    bridge keeps raising as actionable, so the rule must decline them outright."""
    assert BRIDGE_HANDLED_TYPES == frozenset({"tool_execution_risk", "tool_attempt_blocked"})
    routable = {
        "severity": "high",
        "action_taken": "audit",
        "principal_key": "192.168.56.1",
        "matched_summary": {
            "agent_type": "agent_claude_code",
            "findings": [
                {"rule_type": "agent_detect", "type": "agent_behavior", "category": "agent_claude_code", "severity": "low", "counts_as_security_finding": False},
                {"category": "prompt_leak_internal_rules", "severity": "high", "counts_as_security_finding": True, "type": "prompt_leak", "content_source": "tool_result", "message_role": "tool"},
            ],
        },
    }
    for event_type in BRIDGE_HANDLED_TYPES:
        event = dict(routable, event_type=event_type)
        assert trusted_development_route(event) == ({}, False), event_type
    # Same shape, any other event type: routed, which proves the exclusion is what
    # did the work rather than some unrelated condition.
    assert trusted_development_route(dict(routable, event_type="security_check"))[1] is True


def test_reason_names_the_detected_agent_category_verbatim():
    """The reason carries the category the detector actually matched, so an
    operator can grep the finding from the group body without a mapping table."""
    event = {
        "event_type": "phone_cn",
        "severity": "high",
        "action_taken": "audit",
        "principal_key": "192.168.56.1",
        "matched_summary": {
            "findings": [
                {"rule_type": "agent_detect", "category": "agent_openai_codex", "severity": "low", "counts_as_security_finding": False},
                {"category": "phone_cn", "severity": "high", "counts_as_security_finding": True, "content_source": "tool_result"},
            ]
        },
    }
    route, hit = trusted_development_route(event)
    assert hit is True
    assert route["reason"] == "tool_result_of_agent_openai_codex"


MAINTENANCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "maintenance")
REDISPOSITION = os.path.abspath(os.path.join(MAINTENANCE, "redisposition_trusted_dev_alerts.py"))
PLACEHOLDERS = ("__SOURCES__", "__CONFIG__", "__APPLY__")


def guest_template():
    """Pull the GUEST literal out of the maintenance script without importing it
    (importing would need the release helpers and a hypervisor)."""
    with open(REDISPOSITION, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "GUEST":
            return node.value.value
    raise AssertionError("GUEST literal not found in %s" % REDISPOSITION)


def render(apply):
    with open(os.path.join(MAINTENANCE, "trusted_dev_route.py"), "r", encoding="utf-8") as handle:
        rule = handle.read()
    code = guest_template()
    code = code.replace("__SOURCES__", repr([("trusted_dev_route", rule)]))
    code = code.replace("__CONFIG__", repr({"tenant": ""}))
    return code.replace("__APPLY__", repr(apply))


def test_maintenance_template_renders_valid_guest_payload():
    for apply in (False, True):
        code = render(apply)
        ast.parse(code)  # raises SyntaxError if the substitution broke the payload
        for token in PLACEHOLDERS:
            assert token not in code, "%s survived rendering (apply=%s)" % (token, apply)
        assert ("'apply' if True else" in code) is apply
        assert "trusted_development_route" in code


def test_maintenance_template_keeps_the_rule_verbatim():
    # The sweep must run the shipped rule, not a paraphrase: the injected source
    # has to still define the same entry point and version string.
    code = render(False)
    assert "trusted-dev-route-v1" in code
    assert "MACHINE_SOURCES" in code, "the rule source was not injected intact"
