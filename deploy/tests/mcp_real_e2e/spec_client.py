#!/usr/bin/env python3
"""Real-process MCP client and acceptance assertions for JJDGuard.

Secrets are accepted only through environment variables and are never placed
in the machine-readable evidence file.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL = "2025-11-25"


class E2EFailure(RuntimeError):
    pass


class Result:
    def __init__(self, status, headers, raw):
        self.status = status
        self.headers = {str(k).lower(): str(v) for k, v in headers.items()}
        self.raw = raw
        try:
            self.json = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            self.json = None


def http_request(method, url, body=None, headers=None, timeout=35):
    payload = None
    request_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode()
        request_headers.setdefault("Content-Type", "application/json")
    request_headers.setdefault("Accept", "application/json")
    request_headers.setdefault("User-Agent", "JJDGuard-MCP-E2E-SpecClient/1")
    request = urllib.request.Request(
        url, data=payload, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return Result(response.status, response.headers, response.read())
    except urllib.error.HTTPError as exc:
        return Result(exc.code, exc.headers, exc.read())


def require_env(name):
    value = os.environ.get(name, "")
    if not value:
        raise E2EFailure("required secret environment variable is missing: " + name)
    return value


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.admin_initial_password = require_env("MCP_E2E_ADMIN_INITIAL_PASSWORD")
        self.admin_new_password = require_env("MCP_E2E_ADMIN_NEW_PASSWORD")
        self.upstream_token = require_env("MCP_E2E_UPSTREAM_TOKEN")
        self.control_token = require_env("MCP_E2E_CONTROL_TOKEN")
        self.other_tenant_key = require_env("MCP_E2E_OTHER_TENANT_KEY")
        self.chat_only_key = require_env("MCP_E2E_CHAT_ONLY_KEY")
        self.empty_scope_key = require_env("MCP_E2E_EMPTY_SCOPE_KEY")
        self.seeded_gateway_key = require_env("MCP_E2E_GATEWAY_KEY")
        self.drift_token = require_env("MCP_E2E_DRIFT_TOKEN")
        self.admin_token = ""
        self.gateway_key = ""
        self.primary_server_id = ""
        self.poison_server_id = ""
        self.shadow_server_id = ""
        self.drift_server_id = ""
        self.checks = []
        self.object_ids = {}

    def record(self, name, passed, observed=None):
        item = {"name": name, "passed": bool(passed)}
        if observed is not None:
            item["observed"] = observed
        self.checks.append(item)
        if not passed:
            raise E2EFailure(name)

    def cp(self, method, path, body=None, expected=None):
        headers = {}
        if self.admin_token:
            headers["Authorization"] = "Bearer " + self.admin_token
        result = http_request(
            method, self.args.control_url.rstrip("/") + path, body, headers)
        if expected is not None and result.status not in expected:
            code = ""
            if isinstance(result.json, dict):
                error = result.json.get("error")
                if isinstance(error, dict):
                    code = str(error.get("code", ""))
                elif isinstance(error, str):
                    code = error
            raise E2EFailure(
                "control-plane status mismatch on " + path + ": "
                + str(result.status) + " " + code)
        return result

    def control_upstream(self, url, mode, reset=False, delay_ms=0):
        result = http_request("POST", url.rstrip("/") + "/__control", {
            "mode": mode, "reset": reset, "delay_ms": delay_ms,
        }, {"X-E2E-Control-Token": self.control_token})
        if result.status != 200:
            raise E2EFailure("upstream control failed")

    def upstream_state(self, url):
        result = http_request(
            "GET", url.rstrip("/") + "/__state", headers={
                "X-E2E-Control-Token": self.control_token})
        if result.status != 200 or not isinstance(result.json, dict):
            raise E2EFailure("upstream state unavailable")
        return result.json

    def login_and_rotate(self):
        result = http_request(
            "POST", self.args.control_url.rstrip("/") + "/admin/v1/login", {
                "username": self.args.admin_user,
                "password": self.admin_initial_password,
            })
        self.record("bootstrap_admin_login", result.status == 200, result.status)
        self.admin_token = str(result.json.get("token", ""))
        if result.json.get("password_change_required"):
            changed = self.cp("POST", "/admin/v1/me/change-password", {
                "current_password": self.admin_initial_password,
                "new_password": self.admin_new_password,
            }, {200})
            self.record("bootstrap_password_rotated", changed.status == 200)
            self.admin_token = ""
            result = http_request(
                "POST", self.args.control_url.rstrip("/") + "/admin/v1/login", {
                    "username": self.args.admin_user,
                    "password": self.admin_new_password,
                })
            self.record("admin_relogin_after_rotation", result.status == 200)
            self.admin_token = str(result.json.get("token", ""))
        self.record("admin_session_issued", bool(self.admin_token))

    def set_strict_runtime(self):
        result = self.cp("PUT", "/admin/v1/system/settings", {
            "security_audit_only": False,
        }, {200})
        self.record("global_audit_only_disabled", result.status == 200)

    def issue_gateway_key(self):
        self.gateway_key = self.seeded_gateway_key
        self.record("isolated_gateway_key_loaded", bool(self.gateway_key))

    def register_server(self, name, upstream_url, allow_private):
        result = self.cp("POST", "/admin/v1/mcp-servers", {
            "name": name,
            "server_url": upstream_url,
            "owner": "real-e2e",
            "trust_level": "low",
            "status": "active",
            "transport": "streamable_http",
            "auth_token": self.upstream_token,
            "allow_private_egress": allow_private,
            "capabilities": {},
        }, {201})
        server_id = str(result.json.get("id", ""))
        self.record("server_registered_" + name, bool(server_id))
        return server_id

    def update_private_egress(self, server_id, name, upstream_url, allow):
        return self.cp("PUT", "/admin/v1/mcp-servers/" + server_id, {
            "name": name,
            "server_url": upstream_url,
            "owner": "real-e2e",
            "trust_level": "low",
            "status": "active",
            "transport": "streamable_http",
            "auth_token": "",
            "allow_private_egress": allow,
        }, {200})

    def sync(self, server_id):
        return self.cp(
            "POST", "/admin/v1/mcp-servers/" + server_id + "/sync",
            {}, {200})

    def create_policy(self, server_id, session_id, tool, action, priority):
        result = self.cp("POST", "/admin/v1/mcp-policies", {
            "scope_type": "session" if session_id else "tenant",
            "scope_ref": session_id,
            "server_id": server_id,
            "tool_pattern": tool,
            "mode": "strict",
            "default_action": action,
            "priority": priority,
            "enabled": True,
            "note": "real MCP E2E acceptance policy",
        }, {201})
        policy_id = str(result.json.get("id", ""))
        self.record("policy_created_" + action + "_" + (session_id or "tenant"),
                    bool(policy_id))
        return policy_id

    def mcp(self, server_id, identity_session, body, mcp_session="",
            key=None, query_credentials=False, timeout=35):
        key = self.gateway_key if key is None else key
        path = "/mcp/" + urllib.parse.quote(server_id)
        if query_credentials:
            path += "?api_key=" + urllib.parse.quote(key)
            path += "&token=" + urllib.parse.quote(key)
        headers = {
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-JJDGuard-Session-Id": identity_session,
            "X-JJDGuard-Workspace-Id": "mcp-real-e2e",
        }
        if mcp_session:
            headers["Mcp-Session-Id"] = mcp_session
            headers["MCP-Protocol-Version"] = PROTOCOL
        return http_request(
            "POST", self.args.gateway_url.rstrip("/") + path,
            body, headers, timeout=timeout)

    def initialize(self, server_id, identity_session, query_credentials=False,
                   key=None):
        result = self.mcp(server_id, identity_session, {
            "jsonrpc": "2.0", "id": "init-" + identity_session,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "jjdguard-real-e2e", "version": "1"},
            },
        }, key=key, query_credentials=query_credentials)
        session = result.headers.get("mcp-session-id", "")
        return result, session

    def call(self, server_id, identity_session, mcp_session, tool, arguments,
             request_id=None):
        return self.mcp(server_id, identity_session, {
            "jsonrpc": "2.0",
            "id": request_id or ("call-" + identity_session),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }, mcp_session)

    @staticmethod
    def rpc_error_code(result):
        if not isinstance(result.json, dict):
            return None
        error = result.json.get("error")
        return error.get("code") if isinstance(error, dict) else None

    @staticmethod
    def rpc_error_data(result):
        if not isinstance(result.json, dict):
            return {}
        error = result.json.get("error")
        if not isinstance(error, dict):
            return {}
        data = error.get("data")
        return data if isinstance(data, dict) else {}

    @staticmethod
    def rpc_observed(result):
        observed = {"http_status": result.status}
        if not isinstance(result.json, dict):
            observed["json"] = False
            return observed
        error = result.json.get("error")
        if isinstance(error, dict):
            observed["rpc_error_code"] = error.get("code")
            observed["rpc_error_message"] = str(
                error.get("message", ""))[:240]
        else:
            observed["has_result"] = "result" in result.json
        return observed

    def setup_servers_and_assets(self):
        self.control_upstream(self.args.primary_control_url, "clean", True)
        self.control_upstream(self.args.poison_control_url, "poison", True)
        self.control_upstream(self.args.shadow_control_url, "shadow", True)

        self.primary_server_id = self.register_server(
            "e2e-primary", self.args.primary_upstream_url, False)
        denied = self.cp(
            "POST",
            "/admin/v1/mcp-servers/" + self.primary_server_id + "/test-connection",
            {}, {200})
        self.record("private_egress_default_denied",
                    isinstance(denied.json, dict) and not denied.json.get("ok"),
                    denied.json.get("error_kind") if isinstance(denied.json, dict)
                    else "invalid")
        self.update_private_egress(
            self.primary_server_id, "e2e-primary",
            self.args.primary_upstream_url, True)
        connected = self.cp(
            "POST",
            "/admin/v1/mcp-servers/" + self.primary_server_id + "/test-connection",
            {}, {200})
        self.record("private_egress_explicitly_allowed",
                    connected.json.get("ok") is True)
        clean_sync = self.sync(self.primary_server_id)
        self.record("clean_asset_sync", clean_sync.json.get("tool_count") == 2,
                    clean_sync.json.get("tool_count"))
        clean_supply = clean_sync.json.get("supply_chain", {})
        clean_supply_observed = {
            "server_status": clean_supply.get("server_status"),
            "quarantined_tool_count":
                clean_supply.get("quarantined_tool_count"),
            "description_scan_complete":
                clean_supply.get("description_scan_complete"),
            "reasons": clean_supply.get("reasons", []),
        }
        self.record("clean_supply_chain_approved",
                    clean_supply.get("server_status") == "approved" and
                    clean_supply.get("quarantined_tool_count") == 0 and
                    clean_supply.get("description_scan_complete") is True,
                    clean_supply_observed)

        self.poison_server_id = self.register_server(
            "e2e-poison", self.args.poison_upstream_url, True)
        self.shadow_server_id = self.register_server(
            "e2e-shadow", self.args.shadow_upstream_url, True)
        self.drift_server_id = self.register_server(
            "e2e-drift", self.args.primary_upstream_url, True)
        drift_sync = self.sync(self.drift_server_id)
        self.record("drift_server_clean_asset_sync",
                    drift_sync.json.get("tool_count") == 2)
        self.object_ids.update({
            "primary_server": self.primary_server_id,
            "poison_server": self.poison_server_id,
            "shadow_server": self.shadow_server_id,
            "drift_server": self.drift_server_id,
        })

    def setup_policies(self):
        self.create_policy(self.primary_server_id, "", "*", "allow", 10)
        self.create_policy(
            self.primary_server_id, "e2e-audit", "echo", "audit", 100)
        self.create_policy(
            self.primary_server_id, "e2e-block", "echo", "block", 100)
        self.create_policy(
            self.primary_server_id, "e2e-confirm", "echo", "confirm", 100)
        self.create_policy(
            self.primary_server_id, "e2e-admission-floor",
            "dangerous_exec", "allow", 100)
        self.create_policy(
            self.drift_server_id, "e2e-drift",
            "echo", "confirm", 100)

    def assert_protocol_auth_and_isolation(self):
        url = (self.args.gateway_url.rstrip("/") + "/mcp/" +
               urllib.parse.quote(self.primary_server_id))
        init_body = {
            "jsonrpc": "2.0", "id": "init-scope-origin",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "scope-origin-e2e", "version": "1"},
            },
        }
        before_guards = self.upstream_state(
            self.args.primary_control_url)["counts"]["requests"]
        chat_only = http_request("POST", url, init_body, {
            "Authorization": "Bearer " + self.chat_only_key,
        })
        empty_scope = http_request("POST", url, init_body, {
            "Authorization": "Bearer " + self.empty_scope_key,
        })
        untrusted_origin = http_request("POST", url, init_body, {
            "Authorization": "Bearer " + self.gateway_key,
            "Origin": "https://evil.e2e.invalid",
        })
        after_guards = self.upstream_state(
            self.args.primary_control_url)["counts"]["requests"]
        self.record("chat_only_key_rejected_from_mcp",
                    chat_only.status in {401, 403}, chat_only.status)
        self.record("legacy_empty_scope_key_rejected_from_mcp",
                    empty_scope.status in {401, 403}, empty_scope.status)
        self.record("untrusted_browser_origin_rejected",
                    untrusted_origin.status == 403, untrusted_origin.status)
        self.record("scope_and_origin_rejections_not_forwarded",
                    after_guards == before_guards)
        preflight = http_request("OPTIONS", url, headers={
            "Origin": "https://trusted.e2e.invalid",
            "Access-Control-Request-Method": "DELETE",
        })
        self.record("trusted_browser_preflight_allowed",
                    preflight.status == 204 and
                    preflight.headers.get("access-control-allow-origin") ==
                    "https://trusted.e2e.invalid" and
                    "DELETE" in preflight.headers.get(
                        "access-control-allow-methods", ""), preflight.status)

        before = self.upstream_state(self.args.primary_control_url)["counts"]
        init, session = self.initialize(
            self.primary_server_id, "e2e-protocol", query_credentials=True)
        self.record("gateway_initialize_forwarded",
                    init.status == 200 and bool(session), init.status)
        self.record("protocol_2025_11_25_negotiated",
                    init.json["result"]["protocolVersion"] == PROTOCOL)
        listed = self.mcp(self.primary_server_id, "e2e-protocol", {
            "jsonrpc": "2.0", "id": "list-1",
            "method": "tools/list", "params": {},
        }, session)
        self.record("session_bound_tools_list",
                    listed.status == 200 and
                    len(listed.json["result"]["tools"]) == 2)
        state = self.upstream_state(self.args.primary_control_url)
        counts = state["counts"]
        self.record("saved_upstream_token_injected",
                    counts["correct_auth"] >= before["correct_auth"] + 2)
        self.record("caller_token_not_forwarded",
                    counts["caller_auth_forwarded"] == 0)
        self.record("caller_query_credentials_not_forwarded",
                    counts["query_credentials_seen"] == 0)

        deleted_before = counts["sessions_deleted"]
        deleted = http_request("DELETE", url, headers={
            "Authorization": "Bearer " + self.gateway_key,
            "Mcp-Session-Id": session,
            "MCP-Protocol-Version": PROTOCOL,
        })
        state_after_delete = self.upstream_state(self.args.primary_control_url)
        self.record("session_delete_forwarded",
                    deleted.status == 204 and
                    state_after_delete["counts"]["sessions_deleted"] ==
                    deleted_before + 1, deleted.status)
        reused = self.mcp(self.primary_server_id, "e2e-protocol", {
            "jsonrpc": "2.0", "id": "list-after-delete",
            "method": "tools/list", "params": {},
        }, session)
        self.record("deleted_session_cannot_be_reused",
                    reused.status == 404, reused.status)

        counts = self.upstream_state(self.args.primary_control_url)["counts"]

        batch = self.mcp(self.primary_server_id, "e2e-batch", [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        ])
        self.record("json_rpc_batch_rejected",
                    self.rpc_error_code(batch) == -32600,
                    self.rpc_error_code(batch))

        hit_before = counts["requests"]
        other, _ = self.initialize(
            self.primary_server_id, "e2e-other-tenant",
            key=self.other_tenant_key)
        after = self.upstream_state(self.args.primary_control_url)["counts"]
        self.record("cross_tenant_server_hidden", other.status == 404, other.status)
        self.record("cross_tenant_request_not_forwarded",
                    after["requests"] == hit_before)

    def assert_policy_and_admission_floor(self):
        init, allow_session = self.initialize(
            self.primary_server_id, "e2e-allow")
        self.record("allow_initialize", init.status == 200 and bool(allow_session))
        allowed = self.call(
            self.primary_server_id, "e2e-allow", allow_session,
            "echo", {"text": "allow-result"})
        allow_payload = allowed.json if isinstance(allowed.json, dict) else {}
        allow_result = allow_payload.get("result")
        allow_content = (
            allow_result.get("content")
            if isinstance(allow_result, dict) else None
        )
        self.record("allow_forwarded",
                    allowed.status == 200 and
                    isinstance(allow_content, list) and
                    bool(allow_content) and
                    allow_content[0].get("text") == "allow-result",
                    self.rpc_observed(allowed))

        _, audit_session = self.initialize(
            self.primary_server_id, "e2e-audit")
        audited = self.call(
            self.primary_server_id, "e2e-audit", audit_session,
            "echo", {"text": "audit-result"})
        self.record("audit_forwarded",
                    audited.status == 200 and
                    isinstance(audited.json, dict) and
                    "result" in audited.json,
                    self.rpc_observed(audited))

        _, block_session = self.initialize(
            self.primary_server_id, "e2e-block")
        before = self.upstream_state(self.args.primary_control_url)["counts"][
            "tools_call"]
        blocked = self.call(
            self.primary_server_id, "e2e-block", block_session,
            "echo", {"text": "must-not-arrive"})
        after = self.upstream_state(self.args.primary_control_url)["counts"][
            "tools_call"]
        self.record("policy_block_enforced",
                    self.rpc_error_code(blocked) == -32000)
        self.record("blocked_call_not_forwarded", after == before)

        _, admission_session = self.initialize(
            self.primary_server_id, "e2e-admission-floor")
        before = self.upstream_state(self.args.primary_control_url)["counts"][
            "tools_call"]
        protected = self.call(
            self.primary_server_id, "e2e-admission-floor", admission_session,
            "dangerous_exec", {"cmd": "rm -rf /"})
        after = self.upstream_state(self.args.primary_control_url)["counts"][
            "tools_call"]
        self.record("admission_floor_overrides_allow",
                    self.rpc_error_code(protected) == -32000)
        self.record("admission_floor_not_forwarded", after == before)

    def assert_confirmation_exactly_once(self):
        _, session = self.initialize(
            self.primary_server_id, "e2e-confirm")
        before = self.upstream_state(self.args.primary_control_url)["counts"][
            "tools_call"]
        confirmation = self.call(
            self.primary_server_id, "e2e-confirm", session,
            "echo", {"text": "execute-after-approval"},
            request_id="confirm-call-1")
        first_data = self.rpc_error_data(confirmation)
        self.record("confirm_initial_call_blocked",
                    self.rpc_error_code(confirmation) == -32000)
        retried = self.call(
            self.primary_server_id, "e2e-confirm", session,
            "echo", {"text": "execute-after-approval"},
            request_id="confirm-call-1")
        after_retry = self.upstream_state(
            self.args.primary_control_url)["counts"]["tools_call"]
        self.record("confirm_client_retry_blocked_without_forward",
                    self.rpc_error_code(retried) == -32000
                    and after_retry == before)
        retried_data = self.rpc_error_data(retried)
        self.record("confirm_retry_returns_same_identity",
                    bool(first_data.get("confirmation_id"))
                    and first_data.get("confirmation_id")
                    == retried_data.get("confirmation_id")
                    and first_data.get("invocation_id")
                    == retried_data.get("invocation_id"))
        pending = self.cp(
            "GET", "/admin/v1/agentguard/confirmations"
            "?status=pending&source=mcp", expected={200})
        items = pending.json.get("data", [])
        self.record("confirm_record_created", len(items) == 1, len(items))
        self.record("confirm_client_retry_deduplicated",
                    len(items) == 1, len(items))
        confirmation_id = str(items[0]["id"])
        self.object_ids["confirmation"] = confirmation_id
        approved = self.cp(
            "POST", "/admin/v1/agentguard/confirmations/"
            + confirmation_id + "/resolve", {
                "status": "approved",
                "note": "real MCP E2E exact-once approval",
            }, {200})
        approved_state = approved.json if isinstance(approved.json, dict) else {}
        approved_observed = {
            "status": approved_state.get("status"),
            "execution_status": approved_state.get("execution_status"),
            "evidence_status": approved_state.get("evidence_status"),
            "result_available": approved_state.get("result_available"),
        }
        self.record("approved_call_executed",
                    approved_state.get("status") == "approved"
                    and approved_state.get("execution_status") == "executed"
                    and approved_state.get("evidence_status") == "complete"
                    and approved_state.get("result_available") is True,
                    approved_observed)
        after_first = self.upstream_state(
            self.args.primary_control_url)["counts"]["tools_call"]
        self.record("approval_forwards_once", after_first == before + 1,
                    after_first - before)
        delivered = self.call(
            self.primary_server_id, "e2e-confirm", session,
            "echo", {"text": "execute-after-approval"},
            request_id="confirm-call-1")
        delivered_payload = (
            delivered.json if isinstance(delivered.json, dict) else {})
        delivered_result = delivered_payload.get("result")
        delivered_content = (
            delivered_result.get("content")
            if isinstance(delivered_result, dict) else None)
        delivered_text = ""
        if (isinstance(delivered_content, list) and delivered_content
                and isinstance(delivered_content[0], dict)):
            delivered_text = str(delivered_content[0].get("text", ""))
        after_delivery = self.upstream_state(
            self.args.primary_control_url)["counts"]["tools_call"]
        self.record("approved_result_delivered_to_original_client",
                    delivered.status == 200
                    and delivered_text == "execute-after-approval",
                    self.rpc_observed(delivered))
        self.record("approved_result_delivery_no_reexecution",
                    after_delivery == after_first,
                    after_delivery - after_first)

        delivered_again = self.call(
            self.primary_server_id, "e2e-confirm", session,
            "echo", {"text": "execute-after-approval"},
            request_id="confirm-call-1")
        delivered_again_payload = (
            delivered_again.json
            if isinstance(delivered_again.json, dict) else {})
        delivered_again_result = delivered_again_payload.get("result")
        after_second_delivery = self.upstream_state(
            self.args.primary_control_url)["counts"]["tools_call"]
        self.record("approved_result_replay_stable",
                    delivered_again.status == 200
                    and delivered_again_result == delivered_result,
                    self.rpc_observed(delivered_again))
        self.record("approved_result_replay_no_reexecution",
                    after_second_delivery == after_first,
                    after_second_delivery - after_first)
        repeated = self.cp(
            "POST", "/admin/v1/agentguard/confirmations/"
            + confirmation_id + "/resolve", {
                "status": "approved",
                "note": "duplicate approval must not replay",
            }, {200})
        repeated_state = (
            repeated.json if isinstance(repeated.json, dict) else {})
        after_repeat = self.upstream_state(
            self.args.primary_control_url)["counts"]["tools_call"]
        self.record("duplicate_approval_idempotent",
                    repeated_state.get("status") == "approved"
                    and repeated_state.get("execution_status") == "executed"
                    and after_repeat == after_first,
                    {"upstream_delta": after_repeat - after_first})

    def assert_capacity_limit(self):
        self.control_upstream(self.args.primary_control_url, "huge")
        _, session = self.initialize(
            self.primary_server_id, "e2e-capacity")
        result = self.call(
            self.primary_server_id, "e2e-capacity", session,
            "echo", {"text": "bounded"})
        self.record("non_streaming_response_capacity_enforced",
                    result.status == 502, result.status)
        self.control_upstream(self.args.primary_control_url, "clean")

    def assert_approval_context_drift(self):
        _, session = self.initialize(self.drift_server_id, "e2e-drift")
        state_before = self.upstream_state(self.args.primary_control_url)["counts"]
        blocked = self.call(
            self.drift_server_id, "e2e-drift", session,
            "echo", {"text": "must-never-replay-after-drift"},
            request_id="drift-call-1")
        self.record("drift_confirmation_created",
                    self.rpc_error_code(blocked) == -32000)
        error_data = self.rpc_error_data(blocked)
        confirmation_id = str(error_data.get("confirmation_id", ""))
        if not confirmation_id:
            pending = self.cp(
                "GET", "/admin/v1/agentguard/confirmations"
                "?status=pending&source=mcp", expected={200})
            candidates = [
                item for item in pending.json.get("data", [])
                if item.get("tool_call_id") == "drift-call-1"
            ]
            confirmation_id = str(candidates[0]["id"]) if candidates else ""
        self.record("drift_confirmation_identity_available",
                    bool(confirmation_id))
        self.object_ids["drift_confirmation"] = confirmation_id
        self.cp("PUT", "/admin/v1/mcp-servers/" + self.drift_server_id, {
            "name": "e2e-drift",
            "server_url": self.args.primary_upstream_url,
            "owner": "real-e2e",
            "trust_level": "low",
            "status": "active",
            "transport": "streamable_http",
            "auth_token": self.drift_token,
            "allow_private_egress": True,
        }, {200})
        servers = self.cp("GET", "/admin/v1/mcp-servers", expected={200})
        drift_view = next(
            item for item in servers.json.get("servers", [])
            if item.get("id") == self.drift_server_id)
        self.record("route_change_quarantines_server",
                    drift_view.get("admission_status") == "quarantined"
                    and drift_view.get("quarantine_reason") in {
                        "credential_changed", "server_route_changed",
                        "route_binding_changed"})
        resolved = self.cp(
            "POST", "/admin/v1/agentguard/confirmations/"
            + confirmation_id + "/resolve", {
                "status": "approved",
                "note": "must fail closed after approval context drift",
            }, {200})
        resolved_state = (
            resolved.json if isinstance(resolved.json, dict) else {})
        drift_observed = {
            "status": resolved_state.get("status"),
            "execution_status": resolved_state.get("execution_status"),
            "evidence_status": resolved_state.get("evidence_status"),
            "error_code": resolved_state.get("error_code"),
            "result_available": resolved_state.get("result_available"),
        }
        self.record("approval_context_drift_fails_closed",
                    resolved_state.get("status") == "approved"
                    and resolved_state.get("execution_status") == "failed"
                    and resolved_state.get("evidence_status") == "complete"
                    and resolved_state.get("error_code")
                    == "approval_context_drift"
                    and resolved_state.get("result_available") is False,
                    drift_observed)
        state_after = self.upstream_state(self.args.primary_control_url)["counts"]
        self.record("drifted_confirmation_never_reaches_upstream",
                    state_after["requests"] == state_before["requests"])

    @staticmethod
    def admission_facts(sync_payload):
        statuses = []
        reasons = []
        for tool in sync_payload.get("tools", []):
            status = tool.get("admission_status") or tool.get(
                "supply_chain_status") or tool.get("status")
            if status:
                statuses.append(str(status))
            for field in ("admission_reasons", "supply_chain_reasons",
                          "quarantine_reasons"):
                value = tool.get(field)
                if isinstance(value, list):
                    reasons.extend(str(item) for item in value)
            quarantine_reason = tool.get("quarantine_reason")
            if quarantine_reason:
                reasons.append(str(quarantine_reason))
            poison_flags = tool.get("poison_flags")
            if isinstance(poison_flags, list):
                reasons.extend(str(item) for item in poison_flags)
        server_status = sync_payload.get("admission_status") or sync_payload.get(
            "supply_chain_status")
        if server_status:
            statuses.append(str(server_status))
        supply_chain = sync_payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            status = supply_chain.get("server_status")
            if status:
                statuses.append(str(status))
            supply_reasons = supply_chain.get("reasons")
            if isinstance(supply_reasons, list):
                reasons.extend(str(item) for item in supply_reasons)
        return statuses, reasons

    def assert_supply_chain(self):
        poison = self.sync(self.poison_server_id)
        poison_statuses, poison_reasons = self.admission_facts(poison.json)
        poison_text = json.dumps(poison.json, separators=(",", ":")).lower()
        self.record("description_poison_quarantined",
                    "quarantined" in poison_statuses
                    and ("description_poison" in poison_text
                         or "poison" in " ".join(poison_reasons).lower()),
                    {"statuses": poison_statuses, "reasons": poison_reasons})

        shadow = self.sync(self.shadow_server_id)
        shadow_statuses, shadow_reasons = self.admission_facts(shadow.json)
        shadow_text = json.dumps(shadow.json, separators=(",", ":")).lower()
        self.record("shadow_schema_divergence_quarantined",
                    "quarantined" in shadow_statuses
                    and ("shadow_schema_diverges" in shadow_text
                         or "shadow" in " ".join(shadow_reasons).lower()),
                    {"statuses": shadow_statuses, "reasons": shadow_reasons})

        self.control_upstream(self.args.primary_control_url, "rug_pull")
        rug = self.sync(self.primary_server_id)
        rug_statuses, rug_reasons = self.admission_facts(rug.json)
        rug_text = json.dumps(rug.json, separators=(",", ":")).lower()
        self.record("rug_pull_quarantined",
                    rug.json.get("changed") is True
                    and "quarantined" in rug_statuses
                    and ("rug_pull" in rug_text
                         or "rug" in " ".join(rug_reasons).lower()),
                    {"statuses": rug_statuses, "reasons": rug_reasons})

        before = self.upstream_state(
            self.args.poison_control_url)["counts"]["tools_call"]
        _, session = self.initialize(
            self.poison_server_id, "e2e-poison-structural")
        blocked = self.call(
            self.poison_server_id, "e2e-poison-structural", session,
            "echo", {"text": "must-not-arrive"})
        after = self.upstream_state(
            self.args.poison_control_url)["counts"]["tools_call"]
        self.record("quarantine_structural_block",
                    self.rpc_error_code(blocked) == -32000 and after == before)

    def assert_audit_evidence(self):
        time.sleep(1.0)
        result = self.cp(
            "GET", "/admin/v1/audit/tools/high-risk"
            "?risk_level=all&tool_type=mcp&limit=200", expected={200})
        rows = result.json.get("data", [])
        self.record("mcp_tool_audit_rows_persisted", len(rows) >= 6, len(rows))
        facts = {
            (row.get("session_id"), row.get("raw_decision"),
             row.get("effective_decision"), row.get("risk_level"))
            for row in rows
        }
        self.record("audit_decision_facts_persisted",
                    any(x[0] == "e2e-audit" and x[1] == "audit"
                        and x[2] == "audit" for x in facts))
        self.record("admission_floor_fact_persisted",
                    any(x[0] == "e2e-admission-floor"
                        and x[1] == "block" and x[2] == "block"
                        and x[3] == "critical" for x in facts))
        confirmations = self.cp(
            "GET", "/admin/v1/agentguard/confirmations?source=mcp",
            expected={200}).json.get("data", [])
        executed = [
            item for item in confirmations
            if (item.get("mcp_execution") or {}).get("execution_status")
            == "executed"
        ]
        self.record("confirmation_execution_evidence_persisted",
                    len(executed) == 1, len(executed))

    def run(self):
        self.login_and_rotate()
        self.set_strict_runtime()
        self.issue_gateway_key()
        self.setup_servers_and_assets()
        self.setup_policies()
        self.assert_protocol_auth_and_isolation()
        self.assert_policy_and_admission_floor()
        self.assert_confirmation_exactly_once()
        self.assert_capacity_limit()
        self.assert_approval_context_drift()
        self.assert_supply_chain()
        self.assert_audit_evidence()

    def evidence(self, passed, error=""):
        counts = {}
        for name, url in (
            ("primary", self.args.primary_control_url),
            ("poison", self.args.poison_control_url),
            ("shadow", self.args.shadow_control_url),
        ):
            try:
                counts[name] = self.upstream_state(url)["counts"]
            except Exception:
                counts[name] = {"state_unavailable": 1}
        return {
            "schema": "jjdguard.mcp.real-e2e/v1",
            "passed": passed,
            "error": error[:240],
            "protocol": PROTOCOL,
            "checks": self.checks,
            "objects": self.object_ids,
            "upstream_counts": counts,
            "secrets_included": False,
        }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--control-url", required=True)
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--primary-upstream-url", required=True)
    parser.add_argument("--poison-upstream-url", required=True)
    parser.add_argument("--shadow-upstream-url", required=True)
    parser.add_argument("--primary-control-url", required=True)
    parser.add_argument("--poison-control-url", required=True)
    parser.add_argument("--shadow-control-url", required=True)
    parser.add_argument("--evidence", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    acceptance = Acceptance(args)
    passed = False
    error = ""
    try:
        acceptance.run()
        passed = True
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
    evidence = acceptance.evidence(passed, error)
    evidence_path = pathlib.Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({
        "passed": passed,
        "checks_passed": sum(1 for item in acceptance.checks if item["passed"]),
        "checks_total": len(acceptance.checks),
        "evidence": str(evidence_path),
    }, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
