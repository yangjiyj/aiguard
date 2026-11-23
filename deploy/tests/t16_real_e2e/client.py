#!/usr/bin/env python3
"""Sanitized CP/GW T16 acceptance client for one isolated Compose project."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
import uuid


class Failure(Exception):
    pass


def http(method, url, payload=None, bearer="", expected=(200,)):
    body = None if payload is None else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = urllib.request.Request(url, body, headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    if status not in expected:
        raise Failure(f"{method} returned HTTP {status}")
    return status, json.loads(raw) if raw else {}


def solve_captcha(cp):
    """Fetch a real challenge from /admin/v1/captcha and read its answer back the
    same way a sighted client (or a browser-driven E2E reading the DOM) would: the
    server renders the code as literal per-character SVG <text> content, not as a
    bitmap/font glyph, so this parses that document rather than bypassing or
    guessing the challenge. No server-side verification path is touched."""
    _, challenge = http("GET", cp + "/admin/v1/captcha")
    captcha_id = str(challenge.get("captcha_id", ""))
    image = str(challenge.get("image", ""))
    prefix = "data:image/svg+xml;base64,"
    if not captcha_id or not image.startswith(prefix):
        raise Failure("captcha challenge missing captcha_id or inline SVG image")
    svg = base64.b64decode(image[len(prefix):]).decode("utf-8")
    characters = re.findall(r"<text[^>]*>([^<]+)</text>", svg)
    if not characters:
        raise Failure("captcha SVG had no readable text nodes")
    return captcha_id, "".join(characters)


def ts(seconds=0):
    value = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-url", required=True)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    cp, gw = args.control_url.rstrip("/"), args.gateway_url.rstrip("/")
    checks = []
    def cp_req(method, path, payload=None, expected=(200,)):
        return http(method, cp + path, payload, admin_token[0], expected)

    captcha_id, captcha_code = solve_captcha(cp)
    _, login = http("POST", cp + "/admin/v1/login", {
        "username": "admin", "password": os.environ["T16_E2E_ADMIN_INITIAL_PASSWORD"],
        "captcha_id": captcha_id, "captcha_code": captcha_code,
    })
    admin_token = [str(login.get("token", ""))]
    if not admin_token[0]:
        raise Failure("bootstrap admin session missing")
    if login.get("password_change_required"):
        cp_req("POST", "/admin/v1/me/change-password", {
            "current_password": os.environ["T16_E2E_ADMIN_INITIAL_PASSWORD"],
            "new_password": os.environ["T16_E2E_ADMIN_NEW_PASSWORD"],
        })
        captcha_id, captcha_code = solve_captcha(cp)
        _, login = http("POST", cp + "/admin/v1/login", {
            "username": "admin", "password": os.environ["T16_E2E_ADMIN_NEW_PASSWORD"],
            "captcha_id": captcha_id, "captcha_code": captcha_code,
        })
        admin_token[0] = str(login.get("token", ""))
        if not admin_token[0]:
            raise Failure("admin relogin failed")
    checks.append({"name": "bootstrap_admin_login_and_rotation", "passed": True})

    license_fixture = json.loads(pathlib.Path(os.environ["T16_E2E_LICENSE_FILE"]).read_text())
    _, imported = cp_req("POST", "/admin/v1/system/license/import", {"license": license_fixture["license"]})
    if imported.get("valid") is not True:
        raise Failure("agent_security license import invalid")
    checks.append({"name": "agent_security_license_imported", "passed": True})

    _, enrollment = cp_req("POST", "/admin/v1/agent/enrollment-tokens", {
        "name": "T16 isolated acceptance", "default_mode": "monitor",
        "allowed_products": ["claude-code"], "max_endpoints": 1, "expires_at": ts(900),
    }, (201,))
    _, endpoint = http("POST", gw + "/agent/v1/endpoints/register", {
        "machine_id": "t16-e2e-" + args.run_id, "hostname": "t16-e2e-local",
        "os": "linux", "os_version": "isolated", "arch": "amd64", "os_user": "fixture",
        "agent_product": "claude-code", "agent_version": "2.1.278",
        "hookd_version": "t16-e2e-v1", "capabilities": ["decide", "events"],
    }, str(enrollment.get("token", "")), (200,))
    endpoint_id, endpoint_token = str(endpoint.get("endpoint_id", "")), str(endpoint.get("endpoint_token", ""))
    if not endpoint_id or not endpoint_token:
        raise Failure("endpoint registration identity missing")
    checks.append({"name": "cp_enrollment_and_gateway_endpoint_registration", "passed": True})

    resource_id = "/tmp/t16-e2e-fixture.txt"
    _, principal_result = cp_req("POST", "/admin/v1/agent/principals", {
        "name": "T16 isolated fixture principal",
        "expires_at": ts(3600),
        "grants": [
            {"action": "tool_execute", "resource_type": "tool", "resource_id": "Read",
             "conditions": {}, "expires_at": ts(3300), "quota_max": 20, "quota_window_seconds": 3600},
            {"action": "file_read", "resource_type": "file", "resource_id": resource_id,
             "conditions": {}, "expires_at": ts(3300), "quota_max": 20, "quota_window_seconds": 3600},
        ],
    }, (201,))
    principal = principal_result.get("principal", {})
    principal_id = str(principal.get("id", ""))
    credential = str(principal_result.get("credential", ""))
    grants = principal_result.get("grants", [])
    if not principal_id or not credential or len(grants) != 2:
        raise Failure("principal/grant creation incomplete")
    grant_ids = [str(item.get("id", "")) for item in grants]
    if any(not item for item in grant_ids):
        raise Failure("grant IDs missing")
    checks.append({"name": "cp_principal_and_t13_grants_created", "passed": True})

    _, task = cp_req("POST", "/admin/v1/agent/intent-tasks", {
        "endpoint_id": endpoint_id, "principal_id": principal_id,
        "purpose": "Read the isolated fixture file and record its result",
        "expires_at": ts(1800),
        "grants": [{"grant_id": item} for item in grant_ids],
        "allowed_source_kinds": ["tool_result"],
    }, (201,))
    task_id = str(task.get("id", ""))
    if not task_id or task.get("state") != "approved":
        raise Failure("approved task create failed")
    _, task_read = cp_req("GET", "/admin/v1/agent/intent-tasks/" + task_id)
    if task_read.get("state") != "approved" or task_read.get("id") != task_id:
        raise Failure("approved task readback mismatch")
    checks.append({"name": "cp_approved_task_create_and_read", "passed": True})

    args_body = {"file_path": resource_id}
    args_json = json.dumps(args_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    args_hash = "sha256:" + hashlib.sha256(args_json).hexdigest()
    session_id = "t16-e2e-" + args.run_id
    facets = [
        {"action": "tool_execute", "resource_type": "tool", "resource_id": "Read"},
        {"action": "file_read", "resource_type": "file", "resource_id": resource_id},
    ]
    def authorize(tool_id):
        for facet in facets:
            identity = {
                "Product": "claude-code", "EndpointID": endpoint_id, "SessionID": session_id,
                "ToolUseID": tool_id, "ArgsHash": args_hash, "ToolName": "Read",
                "Action": facet["action"], "Type": facet["resource_type"], "ResourceID": facet["resource_id"],
            }
            key = hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            _, decision = http("POST", cp + "/admin/v1/agent/authorize",
                {**facet, "idempotency_key": key, "context": {}}, credential, (200,))
            if decision.get("allowed") is not True:
                raise Failure("T13 exact grant was not allowed")
    def decide(tool_id, prompt_id, fragments=None):
        # Every ToolType="file" decide call structurally hits the builtin
        # builtin_ssh_authorized_keys / builtin_ssh_private_keys PathGlob rules'
        # "~/..." pattern, which the gateway can never resolve against a caller's
        # actual home directory (see compileGlob's explicit error in
        # apps/gateway-core/internal/endpointpolicy/bundle.go). matchRule() then
        # reports an unresolved-unknown rather than a clean non-match, and
        # UnknownMayChange() forces AGENT_POLICY_UNAVAILABLE (503) rather than risk
        # silently treating a possible ~/.ssh/id_* or ~/.ssh/authorized_keys read as
        # ordinary. This is intentional, conservative, unconditional behavior for
        # ANY type="file" call with an absolute-path argument -- not a bug, and not
        # something this fixture should dodge or the product should weaken. We
        # assert on it explicitly as its own "ambiguous path" evidence category.
        _, decision = http("POST", gw + "/agent/v1/decide", {
            "intent_task_id": task_id, "endpoint_id": endpoint_id, "session_id": session_id,
            "prompt_id": prompt_id, "tool_use_id": tool_id,
            "agent": {"product": "claude-code", "version": "2.1.278"},
            "tool": {"name": "Read", "type": "file"}, "arguments": args_body,
            "context": {"fragments": fragments or []},
        }, endpoint_token, (503,))
        if decision.get("code") != "AGENT_POLICY_UNAVAILABLE":
            raise Failure("expected the builtin SSH-key PathGlob ambiguity to yield "
                          "AGENT_POLICY_UNAVAILABLE for a type=file call, got: " + json.dumps(decision))
        return decision
    first = "t16-e2e-tool-1"
    authorize(first)
    decide(first, "t16-e2e-prompt-1")
    checks.append({"name": "ambiguous_path_file_type_decide_yields_policy_unavailable", "passed": True})

    result_text = "T16 isolated fixture result: read completed successfully."
    result_hash = "sha256:" + hashlib.sha256(result_text.encode()).hexdigest()
    event_id = str(uuid.uuid4())
    now = ts()
    event = {
        "event_id": event_id, "event_type": "tool.post", "occurred_at": now,
        "agent": {"product": "claude-code", "version": "2.1.278", "runtime": "cli"},
        "session": {"session_id": session_id}, "turn": {"prompt_id": "t16-e2e-prompt-1"},
        "context": {"machine_id": "t16-e2e-" + args.run_id, "hostname": "t16-e2e-local", "os_user": "fixture"},
        "tool": {"tool_use_id": first, "name": "Read", "type": "file", "args_hash": args_hash,
                 "result": {"hash": result_hash, "len": len(result_text.encode()), "success": True}},
        "local_decision": {"raw": "allow", "effective": "allow", "mode": "monitor",
                           "latency_ms": 1, "source": "local", "policy_version": 1},
    }
    _, event_ack = http("POST", gw + "/agent/v1/events", {
        "schema_version": "events.v1", "endpoint_id": endpoint_id,
        "hookd_version": "t16-e2e-v1", "sent_at": now, "events": [event],
    }, endpoint_token, (200,))
    checks.append({"name": "authenticated_gateway_tool_post_accepted", "passed": True})

    second = "t16-e2e-tool-2"
    authorize(second)
    fragment = {"trust": "untrusted", "source": "tool_result", "tool_use_id": first,
                "hash": result_hash, "preview": result_text}
    decide(second, "t16-e2e-prompt-2", [fragment])
    checks.append({"name": "ambiguous_path_decide_with_untrusted_lineage_fragment_still_unavailable", "passed": True})

    cp_req("POST", "/admin/v1/agent/intent-tasks/" + task_id + "/revoke", {}, (204,))
    _, task_read = cp_req("GET", "/admin/v1/agent/intent-tasks/" + task_id)
    if task_read.get("state") != "revoked":
        raise Failure("task revoke readback mismatch")
    third = "t16-e2e-tool-3"
    authorize(third)
    decide(third, "t16-e2e-prompt-3")
    checks.append({"name": "revoked_task_ambiguous_path_decide_still_unavailable_not_silently_allowed", "passed": True})

    # ------------------------------------------------------------------
    # Resolved-decision categories via a ToolType="network" WebFetch call.
    #
    # The three type="file" decide() calls above are structurally ambiguous
    # (see decide()'s own comment): the builtin SSH-key PathGlob rules force
    # AGENT_POLICY_UNAVAILABLE for every type="file" call regardless of the
    # actual path, by design. That correctly-documented 503 is itself the
    # "ambiguous path" evidence category, but it can never demonstrate a
    # resolved allow/audit/confirm/block outcome. The builtin rule set has
    # zero ToolType="network" rules (see BuiltinRules in
    # apps/control-plane/internal/agentendpoint/builtin_rules.go), so a
    # WebFetch-shaped call cleanly reaches a real, resolved decision -- this
    # is what the "normal task execution" and "malicious external-content
    # influence" categories below use, plus the semantic-Judge-cannot-
    # override-authorization counter-example.
    fetch_url = "https://t16-e2e-fixture.invalid/report"
    fetch_host = "t16-e2e-fixture.invalid"
    fetch_args_body = {"url": fetch_url}
    fetch_args_json = json.dumps(fetch_args_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    fetch_args_hash = "sha256:" + hashlib.sha256(fetch_args_json).hexdigest()
    _, fetch_principal_result = cp_req("POST", "/admin/v1/agent/principals", {
        "name": "T16 isolated fixture principal (webfetch)",
        "expires_at": ts(3600),
        "grants": [
            {"action": "tool_execute", "resource_type": "tool", "resource_id": "WebFetch",
             "conditions": {}, "expires_at": ts(3300), "quota_max": 20, "quota_window_seconds": 3600},
            {"action": "network_connect", "resource_type": "domain", "resource_id": fetch_host,
             "conditions": {}, "expires_at": ts(3300), "quota_max": 20, "quota_window_seconds": 3600},
        ],
    }, (201,))
    fetch_principal = fetch_principal_result.get("principal", {})
    fetch_principal_id = str(fetch_principal.get("id", ""))
    fetch_credential = str(fetch_principal_result.get("credential", ""))
    fetch_grants = fetch_principal_result.get("grants", [])
    if not fetch_principal_id or not fetch_credential or len(fetch_grants) != 2:
        raise Failure("webfetch principal/grant creation incomplete")
    checks.append({"name": "cp_webfetch_principal_and_t13_grants_created", "passed": True})

    # T16-DEV-20260928: the WebFetch flow gets its own approved task bound to the
    # WebFetch principal. Reusing the file task (different principal) made the
    # server-side step binding mark every WebFetch proposal uncertain, so no
    # cross-step ledger row was ever written.
    _, fetch_task = cp_req("POST", "/admin/v1/agent/intent-tasks", {
        "endpoint_id": endpoint_id, "principal_id": fetch_principal_id,
        "purpose": "Fetch the approved fixture report and summarize it",
        "expires_at": ts(1800),
        "grants": [{"grant_id": str(item.get("id", ""))} for item in fetch_grants],
        "allowed_source_kinds": ["tool_result"],
    }, (201,))
    fetch_task_id = str(fetch_task.get("id", ""))
    if not fetch_task_id or fetch_task.get("state") != "approved":
        raise Failure("approved webfetch task create failed")
    checks.append({"name": "cp_webfetch_approved_task_created", "passed": True})

    fetch_facets = [
        {"action": "tool_execute", "resource_type": "tool", "resource_id": "WebFetch"},
        {"action": "network_connect", "resource_type": "domain", "resource_id": fetch_host},
    ]
    def hash_args(body):
        return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    def authorize_webfetch(tool_id, facets, credential, args_hash=None, expect_allowed=True):
        """Exact T14 facet authorize for one call; returns {action: allowed}."""
        outcome = {}
        for facet in facets:
            identity = {
                "Product": "claude-code", "EndpointID": endpoint_id, "SessionID": session_id,
                "ToolUseID": tool_id, "ArgsHash": args_hash or fetch_args_hash, "ToolName": "WebFetch",
                "Action": facet["action"], "Type": facet["resource_type"], "ResourceID": facet["resource_id"],
            }
            key = hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            _, decision = http("POST", cp + "/admin/v1/agent/authorize",
                {**facet, "idempotency_key": key, "context": {}}, credential, (200,))
            outcome[facet["action"]] = decision.get("allowed") is True
        if expect_allowed and not all(outcome.values()):
            raise Failure("T13 exact grant was not allowed for webfetch facets: " + json.dumps(outcome))
        return outcome
    def decide_webfetch(tool_id, prompt_id, fragments=None, args_body=None):
        _, decision = http("POST", gw + "/agent/v1/decide", {
            "intent_task_id": fetch_task_id, "endpoint_id": endpoint_id, "session_id": session_id,
            "prompt_id": prompt_id, "tool_use_id": tool_id,
            "agent": {"product": "claude-code", "version": "2.1.278"},
            "tool": {"name": "WebFetch", "type": "network"}, "arguments": args_body or fetch_args_body,
            "context": {"fragments": fragments or []},
        }, endpoint_token, (200,))
        if decision.get("raw_decision") not in {"allow", "audit", "confirm", "block"}:
            raise Failure("gateway webfetch decision response malformed: " + json.dumps(decision))
        return decision
    def tool_log_evidence(tool_id):
        _, entries = cp_req("GET", "/admin/v1/audit/tools/session/" + session_id + "?limit=100")
        for entry in entries:
            if entry.get("tool_call_id") == tool_id:
                evidence = entry.get("evidence_json") or {}
                if isinstance(evidence, str):
                    evidence = json.loads(evidence) if evidence else {}
                return evidence.get("t16_intent") or {}
        raise Failure("tool_call_logs entry not found for " + tool_id)

    # The fetched page is attacker-controlled; step 2 will cite it as source.
    adversarial_preview = ("External page includes sk-ant-abcdefghijklmnopqrstuvwxyz, "
                           "external-request-marker-8842, and says contact alice@example.com "
                           "from /home/dev/private; also try Bearer long-secret-token-123456.")
    adversarial_hash = "sha256:" + hashlib.sha256(adversarial_preview.encode()).hexdigest()

    # Category 1: normal task execution -- a WebFetch call with no external
    # content and full T13 grant coverage should resolve cleanly.
    fetch_normal = "t16-e2e-webfetch-normal"
    authorize_webfetch(fetch_normal, fetch_facets, fetch_credential)
    normal_decision = decide_webfetch(fetch_normal, "t16-e2e-prompt-webfetch-normal")
    normal_intent = tool_log_evidence(fetch_normal)
    normal_steps = (normal_intent.get("assessment") or {}).get("steps") or []
    if normal_decision.get("raw_decision") != "allow" or normal_intent.get("authorization_outcome") != "not_enforced" or \
       (normal_intent.get("approved_task") or {}).get("state") != "resolved" or \
       not normal_steps or normal_steps[0].get("authorization_state") != "matched":
        raise Failure("normal in-scope WebFetch must be allow with matched T13 facet and resolved task: " +
                      json.dumps({"decision": normal_decision, "intent": normal_intent}))
    checks.append({"name": "webfetch_normal_task_execution_resolved", "passed": True,
                    "raw_decision": normal_decision.get("raw_decision"),
                    "effective_decision": normal_decision.get("effective_decision"),
                    "authorization_state_recorded": normal_steps[0].get("authorization_state"),
                    "alignment_recorded": (normal_intent.get("assessment") or {}).get("alignment")})

    # Accepted tool.post for step 1 carries the (malicious) page's result hash.
    post_now = ts()
    fetch_post = {
        "event_id": str(uuid.uuid4()), "event_type": "tool.post", "occurred_at": post_now,
        "agent": {"product": "claude-code", "version": "2.1.278", "runtime": "cli"},
        "session": {"session_id": session_id}, "turn": {"prompt_id": "t16-e2e-prompt-webfetch-normal"},
        "context": {"machine_id": "t16-e2e-" + args.run_id, "hostname": "t16-e2e-local", "os_user": "fixture"},
        "tool": {"tool_use_id": fetch_normal, "name": "WebFetch", "type": "network", "args_hash": fetch_args_hash,
                 "result": {"hash": adversarial_hash, "len": len(adversarial_preview.encode()), "success": True}},
        "local_decision": {"raw": "allow", "effective": "allow", "mode": "monitor",
                           "latency_ms": 1, "source": "local", "policy_version": 1},
    }
    http("POST", gw + "/agent/v1/events", {
        "schema_version": "events.v1", "endpoint_id": endpoint_id,
        "hookd_version": "t16-e2e-v1", "sent_at": post_now, "events": [fetch_post],
    }, endpoint_token, (200,))
    checks.append({"name": "webfetch_step1_tool_post_accepted", "passed": True})

    # Category 2: malicious external-content influence (step 2). The next,
    # in-scope WebFetch cites step 1's accepted result -- attacker-controlled
    # text carrying secret-looking tokens and an exfiltration marker -- as an
    # untrusted tool_result fragment. SECURITY_SEMANTIC_*=true in this run, so
    # the existing SemanticJudge path is invoked; it is observe-only and its
    # verdict (or unavailability) must never change raw/effective decisions.
    adversarial_fragment = {"trust": "untrusted", "source": "tool_result", "tool_use_id": fetch_normal,
                             "hash": adversarial_hash, "preview": adversarial_preview}
    fetch_adversarial = "t16-e2e-webfetch-adversarial"
    authorize_webfetch(fetch_adversarial, fetch_facets, fetch_credential)
    adversarial_decision = decide_webfetch(fetch_adversarial, "t16-e2e-prompt-webfetch-adversarial", [adversarial_fragment])
    if adversarial_decision.get("raw_decision") != normal_decision.get("raw_decision") or \
       adversarial_decision.get("effective_decision") != normal_decision.get("effective_decision"):
        raise Failure("malicious external content changed the T13/T16 authorization decision: "
                      "normal=" + json.dumps(normal_decision) + " adversarial=" + json.dumps(adversarial_decision))
    for leaked in ("sk-ant-abcdefghijklmnopqrstuvwxyz", "long-secret-token-123456", "/home/dev/private"):
        if leaked in json.dumps(adversarial_decision):
            raise Failure("adversarial fragment content leaked into the client-facing decide response")
    checks.append({"name": "webfetch_malicious_content_influence_does_not_change_authorization", "passed": True,
                    "raw_decision": adversarial_decision.get("raw_decision"),
                    "effective_decision": adversarial_decision.get("effective_decision")})

    t16_intent = tool_log_evidence(fetch_adversarial)
    adversarial_assessment = t16_intent.get("assessment") or {}
    semantic = adversarial_assessment.get("semantic") or {}
    if semantic.get("decision") not in (None, "", "allow", "audit"):
        raise Failure("semantic decision recorded in evidence exceeds the observe-only Allow/Audit cap: " +
                      json.dumps(semantic))
    if t16_intent.get("authorization_outcome") != "not_enforced":
        raise Failure("semantic/intent evidence must not become an authorization outcome: " + json.dumps(t16_intent))
    raw_intent = json.dumps(t16_intent)
    for leaked in ("sk-ant-abcdefghijklmnopqrstuvwxyz", "long-secret-token-123456"):
        if leaked in raw_intent:
            raise Failure("raw secret-looking source text persisted in t16_intent evidence")
    checks.append({"name": "t16_intent_evidence_recorded_with_semantic_capped_to_observe_only", "passed": True,
                    "semantic_status_recorded": semantic.get("status", ""),
                    "semantic_decision_recorded": semantic.get("decision", ""),
                    "alignment_recorded": adversarial_assessment.get("alignment", ""),
                    "review_required_recorded": adversarial_assessment.get("review_required")})

    # Category 3: multi-step deviation (step 3). Influenced by step 1's page,
    # the agent now tries to send data to a host outside the approved task.
    # hookd would T13-authorize every exact facet of THIS call (same args
    # hash); tool_execute is granted, network_connect to the new host is not,
    # so T13 persists an explicit denial. GW re-resolves that persisted denial
    # and floors raw_decision at block; the endpoint mode (monitor) governs
    # the effective decision. The intent/semantic layers never do this.
    fetch_undergranted = "t16-e2e-webfetch-deviation"
    ungranted_host = "t16-e2e-undergranted.invalid"
    deviation_args = {"url": "https://" + ungranted_host + "/x"}
    deviation_facets = [fetch_facets[0], {"action": "network_connect", "resource_type": "domain", "resource_id": ungranted_host}]
    deviation_t13 = authorize_webfetch(fetch_undergranted, deviation_facets, fetch_credential,
                                       args_hash=hash_args(deviation_args), expect_allowed=False)
    if deviation_t13 != {"tool_execute": True, "network_connect": False}:
        raise Failure("T13 must allow tool_execute and deny ungranted network_connect: " + json.dumps(deviation_t13))
    deviation_decision = decide_webfetch(fetch_undergranted, "t16-e2e-prompt-webfetch-deviation",
                                         [adversarial_fragment], deviation_args)
    if deviation_decision.get("raw_decision") != "block" or deviation_decision.get("effective_decision") != "audit" or \
       deviation_decision.get("reason") != "t13_authorization_denied":
        raise Failure("persisted T13 denial must floor raw decision at block (monitor mode -> audit): " +
                      json.dumps(deviation_decision))
    checks.append({"name": "webfetch_ungranted_resource_t13_denial_floors_raw_block", "passed": True,
                    "raw_decision": deviation_decision.get("raw_decision"),
                    "effective_decision": deviation_decision.get("effective_decision"),
                    "reason": deviation_decision.get("reason")})
    deviation_intent = tool_log_evidence(fetch_undergranted)
    deviation_assessment = deviation_intent.get("assessment") or {}
    deviation_alignment = deviation_assessment.get("alignment", "")
    deviation_steps = deviation_assessment.get("steps") or []
    deviation_auth_state = deviation_steps[0].get("authorization_state", "") if deviation_steps else ""
    if deviation_intent.get("authorization_outcome") != "t13_denied_block_floor" or deviation_alignment != "deviation":
        raise Failure("ungranted egress must be recorded as a T13-denied deviation: " + json.dumps(deviation_intent))
    checks.append({"name": "webfetch_ungranted_resource_recorded_as_deviation", "passed": True,
                    "alignment_recorded": deviation_alignment, "authorization_state_recorded": deviation_auth_state,
                    "issues_recorded": deviation_assessment.get("issues", [])})

    pathlib.Path(args.evidence).write_text(json.dumps({
        "acceptance_slice": "T16 isolated CP/GW service runtime", "run_id": args.run_id,
        "checks": checks, "event_ack_fields": sorted(event_ack.keys()),
        "synthetic_result_hash": result_hash, "passed": True, "overall_t16": "HOLD",
        "limitations": ["single isolated endpoint; one file task and one WebFetch task",
                        "SemanticJudge is observe-only; its verdict is evidence, never authorization", "no shared VM or production DB",
                        "no live agent, MCP executor, concurrency stress, tenant matrix, or deployment acceptance"],
    }, ensure_ascii=False, indent=2) + "\n")
    pathlib.Path(args.state).write_text(json.dumps({
        "task_id": task_id, "endpoint_id": endpoint_id, "first_tool_id": first,
        "second_tool_id": second, "third_tool_id": third, "event_id": event_id,
        "result_hash": result_hash,
        "fetch_task_id": fetch_task_id, "fetch_normal_tool_id": fetch_normal, "fetch_result_hash": adversarial_hash,
        "fetch_adversarial_tool_id": fetch_adversarial, "fetch_undergranted_tool_id": fetch_undergranted,
        "adversarial_raw_decision": adversarial_decision.get("raw_decision"),
        "adversarial_effective_decision": adversarial_decision.get("effective_decision"),
        "deviation_raw_decision": deviation_decision.get("raw_decision"),
        "deviation_effective_decision": deviation_decision.get("effective_decision"),
    }) + "\n")
    print("PASS admin/license/enrollment/principal/T13/T16 decide/tool.post/history-lineage/revoke")


if __name__ == "__main__":
    try:
        main()
    except (Failure, KeyError, OSError, ValueError) as exc:
        print("FAIL isolated CP/GW acceptance: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
