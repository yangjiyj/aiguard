#!/usr/bin/env python3
"""Plan-first controlled T22 parent/child delegation acceptance runner.

Default invocation is offline. Apply mode calls only the official T22/T13 API;
it does not apply migrations or execute a downstream business mutation.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

SCHEMA = "t22.acceptance-runner.v1"
PRIVATE_SCHEMA = "t22.acceptance-private-input.v1"
GATE_SCHEMA = "t22.runtime-gate.v1"
FIXTURE_SCHEMA = "t22.parent-fixture.v1"
T22_COMMIT = "cc6f820b0f3422f55bd6fcc6511e898f395e1cb7"
T22_TREE = "889647de1ccf9332a7269a8f282e9c2ef9308dbf"
EXPECTED_ACCEPTS = ("T13.accept", "T15.accept", "T17.accept")
EXPECTED_MIGRATIONS = tuple(range(861, 867)) + (868,)
MIGRATION_HASHES = {
    861: "c59fc56888427f9db17dfd97fbc031c678cce8ac14ca1a6f655e17865e9da862",
    862: "1e897afea24bba263e93bebc9e3d903f6286756cf14552b76db8e3c7c8db0d2b",
    863: "36b8991bce3f35e4d296c48bbd930d61959bdaf36023b73eb4a392be87e96fe0",
    864: "26c2ddd010466ba8b4f8adf5b40b6b649752cd740d93a43837eff47fe9bb5975",
    865: "a36b255223027f1b5ad0a761bd5e8cb11e1156089e5cc0860e720b2aea89d3f4",
    866: "2ccd162e4181d6199fcf84cfbf04e88b990ed15d6ab69a8f250548161067de36",
    868: "8dc50945f3828b6384be3a79bff61efa529a09f537aa2b29e39d39927b70b89c",
}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{16,128}$")
SENSITIVE_KEY_RE = re.compile(r"(token|secret|password|credential|authorization)", re.I)
CALL_FIELDS = (
    "id", "delegation_id", "parent_principal_id", "child_principal_id",
    "calling_principal_id", "project_id", "action", "resource_type", "resource_id",
    "authorization_idempotency_key", "request_hash", "run_id", "instance_id",
    "tool_call_id", "allowed", "reason", "created_at",
)


class GateError(Exception):
    pass


class RunError(Exception):
    def __init__(self, code: str, unknown_outcome: bool = False):
        super().__init__(code)
        self.code = code
        self.unknown_outcome = unknown_outcome


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise GateError(label + "_missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GateError(label + "_invalid") from None
    if parsed.tzinfo is None:
        raise GateError(label + "_timezone_missing")
    return parsed.astimezone(dt.timezone.utc)


def read_bytes(path_value: Any, private: bool = False, limit: int = 2 * 1024 * 1024) -> bytes:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise GateError("absolute_file_path_required")
    try:
        st = os.lstat(path_value)
    except OSError:
        raise GateError("input_file_unavailable") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise GateError("input_file_must_be_regular")
    if private:
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise GateError("private_file_owner_mismatch")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise GateError("private_file_permissions_too_open")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path_value, flags)
        with os.fdopen(fd, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode):
                raise GateError("input_file_changed")
            if private and stat.S_IMODE(current.st_mode) & 0o077:
                raise GateError("private_file_permissions_too_open")
            raw = stream.read(limit + 1)
    except GateError:
        raise
    except OSError:
        raise GateError("input_file_unavailable") from None
    if len(raw) > limit:
        raise GateError("input_file_too_large")
    return raw


def read_json(path_value: Any, private: bool = False) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path_value, private))
    except (ValueError, UnicodeDecodeError):
        raise GateError("input_json_invalid") from None
    if not isinstance(value, dict):
        raise GateError("input_json_object_required")
    return value


def file_receipt(ref: Any, label: str) -> tuple[dict[str, Any], str]:
    if not isinstance(ref, dict) or not isinstance(ref.get("sha256"), str) or not SHA_RE.fullmatch(ref["sha256"]):
        raise GateError(label + "_receipt_invalid")
    raw = read_bytes(ref.get("path"))
    actual = hashlib.sha256(raw).hexdigest()
    if actual != ref["sha256"]:
        raise GateError(label + "_receipt_hash_mismatch")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise GateError(label + "_receipt_json_invalid") from None
    if not isinstance(obj, dict):
        raise GateError(label + "_receipt_object_required")
    return obj, actual


def require_id(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise GateError(label + "_invalid")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        raise GateError(label + "_invalid")
    return value


def scalar_map(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(label + "_must_be_object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 128 or SENSITIVE_KEY_RE.search(key):
            raise GateError(label + "_sensitive_or_invalid_key")
        if not isinstance(item, (str, int, float, bool)) and item is not None:
            raise GateError(label + "_non_scalar_value")
        if isinstance(item, str) and (len(item) > 512 or any(ord(ch) < 0x20 for ch in item)):
            raise GateError(label + "_invalid_text")
        if isinstance(item, float) and not math.isfinite(item):
            raise GateError(label + "_non_finite_number")
        result[key] = item
    return result


def validate_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise GateError("api_url_invalid")
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        raise GateError("api_url_invalid")
    if parts.query or parts.fragment:
        raise GateError("api_url_query_or_fragment_forbidden")
    if parts.scheme != "https" and parts.hostname not in ("127.0.0.1", "::1", "localhost"):
        raise GateError("remote_http_forbidden")
    return value.rstrip("/")


def validate_grant(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise GateError(label + "_invalid")
    grant = {
        "action": require_id(raw.get("action"), label + "_action", 64),
        "resource_type": require_id(raw.get("resource_type"), label + "_resource_type", 64),
        "resource_id": require_id(raw.get("resource_id"), label + "_resource_id"),
        "conditions": scalar_map(raw.get("conditions", {}), label + "_conditions"),
        "expires_at": parse_time(raw.get("expires_at"), label + "_expires_at"),
        "quota_max": raw.get("quota_max"),
        "quota_window_seconds": raw.get("quota_window_seconds"),
    }
    for field in ("quota_max", "quota_window_seconds"):
        if isinstance(grant[field], bool) or not isinstance(grant[field], int) or grant[field] < 1:
            raise GateError(label + "_" + field + "_invalid")
    return grant


def verify_ref_status(ref: Any, label: str, accepted: tuple[str, ...] = ("PASS", "ACCEPTED", "DONE")) -> list[str]:
    try:
        data, _ = file_receipt(ref, label)
    except GateError as exc:
        return [str(exc)]
    status = data.get("status") or data.get("verdict") or data.get("review_verdict")
    return [] if isinstance(status, str) and status.upper() in accepted else [label + "_receipt_not_accepted"]


def verify_t22_source_review(review: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(review, dict) or review.get("status") not in ("PASS", "PASS_SOURCE_DELTA_ONLY"):
        return ["t22_source_review_not_passed"]
    if review.get("candidate_commit") != T22_COMMIT or review.get("candidate_tree") != T22_TREE:
        errors.append("t22_source_review_gate_pin_mismatch")
    try:
        receipt, _ = file_receipt(review.get("receipt"), "t22_source_review")
    except GateError as exc:
        return errors + [str(exc)]
    if receipt.get("verdict") != "PASS_SOURCE_DELTA_ONLY":
        errors.append("t22_source_review_receipt_verdict_mismatch")
    candidate = receipt.get("candidate")
    if not isinstance(candidate, dict) or candidate.get("commit") != T22_COMMIT or candidate.get("tree") != T22_TREE:
        errors.append("t22_source_review_receipt_candidate_mismatch")
    return errors


def verify_dependency_acceptance(item: Any, node: str) -> list[str]:
    label = node.lower().replace(".", "_")
    if not isinstance(item, dict) or item.get("status") != "ACCEPTED":
        return [label + "_not_accepted"]
    digest = item.get("candidate_digest")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        return [label + "_candidate_digest_invalid"]
    try:
        receipt, _ = file_receipt(item.get("receipt"), label)
    except GateError as exc:
        return [str(exc)]
    errors: list[str] = []
    if receipt.get("schema") != "agent-platform.controller-acceptance-record.v1":
        errors.append(label + "_canonical_receipt_schema_mismatch")
    if receipt.get("node_id") != node:
        errors.append(label + "_canonical_receipt_node_mismatch")
    if receipt.get("candidate_digest") != digest:
        errors.append(label + "_canonical_candidate_digest_mismatch")
    if receipt.get("status") != "ACCEPTED":
        errors.append(label + "_canonical_receipt_not_accepted")
    if receipt.get("review_verdict") not in ("PASS", "ACCEPTED"):
        errors.append(label + "_canonical_review_verdict_not_passed")
    return errors


def validate_gate(gate: dict[str, Any], private: dict[str, Any], fixture: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if gate.get("schema") != GATE_SCHEMA:
        errors.append("runtime_gate_schema_mismatch")
    if gate.get("apply_authorized") is not True:
        errors.append("root_apply_authorization_missing")
    if gate.get("scope_policy") != "dedicated_test_environment" or gate.get("is_production") is not False:
        errors.append("dedicated_nonproduction_target_not_verified")
    if gate.get("api_base_url") != private["api_base_url"]:
        errors.append("api_target_pin_mismatch")
    if gate.get("tenant_id") != private["tenant_id"] or gate.get("project_id") != private["project_id"]:
        errors.append("tenant_project_pin_mismatch")

    review = gate.get("t22_source_review")
    errors.extend(verify_t22_source_review(review))

    accepts = gate.get("dependency_acceptances")
    if not isinstance(accepts, dict):
        errors.append("dependency_acceptances_missing")
    else:
        for node in EXPECTED_ACCEPTS:
            errors.extend(verify_dependency_acceptance(accepts.get(node), node))

    server = gate.get("server")
    if not isinstance(server, dict):
        errors.append("server_runtime_pin_missing")
    else:
        for field in ("source_commit", "source_tree"):
            if not isinstance(server.get(field), str) or not re.fullmatch(r"[0-9a-f]{40}", server[field]):
                errors.append("server_" + field + "_invalid")
        if not isinstance(server.get("binary_sha256"), str) or not SHA_RE.fullmatch(server["binary_sha256"]):
            errors.append("server_binary_sha256_invalid")
        included = server.get("included_commits")
        if not isinstance(included, list) or T22_COMMIT not in included:
            errors.append("server_missing_cc6f820_ancestry_pin")
        process = server.get("process_identity")
        if not isinstance(process, dict) or not isinstance(process.get("pid"), int) or process.get("pid", 0) < 1:
            errors.append("server_process_pid_missing")
        elif not isinstance(process.get("start_ticks"), str) or not process["start_ticks"].isdigit():
            errors.append("server_process_start_ticks_invalid")
        elif not isinstance(process.get("exe_sha256"), str) or not SHA_RE.fullmatch(process["exe_sha256"]):
            errors.append("server_process_exe_sha256_invalid")
        elif process.get("exe_sha256") != server.get("binary_sha256"):
            errors.append("server_process_executable_hash_mismatch")

    t15 = gate.get("t15_context_contract")
    context_fields = {"run_id", "instance_id", "tool_call_id"}
    if not isinstance(t15, dict) or t15.get("status") != "ACCEPTED":
        errors.append("t15_context_contract_not_accepted")
    else:
        request_fields = t15.get("request_context_fields")
        claim_fields = t15.get("claim_context_fields")
        if not isinstance(request_fields, list) or set(request_fields) != context_fields:
            errors.append("t15_request_context_fields_mismatch")
        if not isinstance(claim_fields, list) or set(claim_fields) != context_fields:
            errors.append("t15_claim_context_fields_mismatch")
        if t15.get("same_context_reauthorization") is not True:
            errors.append("t15_same_context_reauthorization_unproven")

    migration = gate.get("migration")
    if not isinstance(migration, dict):
        errors.append("migration_ledger_missing")
    else:
        if migration.get("status") != "VERIFIED_APPLIED" or migration.get("full_ledger_verified") is not True:
            errors.append("migration_full_ledger_not_verified")
        if not isinstance(migration.get("database_identity_sha256"), str) or not SHA_RE.fullmatch(migration["database_identity_sha256"]):
            errors.append("database_identity_hash_missing")
        try:
            file_receipt(migration.get("ledger_receipt"), "migration_ledger")
        except GateError as exc:
            errors.append(str(exc))
        rows = migration.get("applied")
        if not isinstance(rows, list):
            errors.append("migration_applied_rows_missing")
        else:
            by_version = {row.get("version"): row for row in rows if isinstance(row, dict) and isinstance(row.get("version"), int)}
            for version in EXPECTED_MIGRATIONS:
                row = by_version.get(version)
                if not isinstance(row, dict) or row.get("applied") is not True:
                    errors.append(f"migration_{version}_not_applied")
                    continue
                source_hash = row.get("source_sha256")
                if not isinstance(source_hash, str) or not SHA_RE.fullmatch(source_hash):
                    errors.append(f"migration_{version}_source_hash_missing")
                elif version in MIGRATION_HASHES and source_hash != MIGRATION_HASHES[version]:
                    errors.append(f"migration_{version}_source_hash_mismatch")
            found = [row.get("version") for row in rows if isinstance(row, dict) and row.get("version") in EXPECTED_MIGRATIONS]
            if found != sorted(set(found)) or not set(EXPECTED_MIGRATIONS).issubset(found):
                errors.append("migration_order_incomplete")

    license_gate = gate.get("feature_license")
    if not isinstance(license_gate, dict) or license_gate.get("status") != "ACTIVE":
        errors.append("agent_security_license_not_active")
    else:
        errors.extend(verify_ref_status(license_gate.get("receipt"), "feature_license", ("ACTIVE", "PASS", "ACCEPTED")))

    clock = gate.get("clock")
    if not isinstance(clock, dict) or clock.get("offset_verified") is not True:
        errors.append("server_clock_offset_not_verified")
    else:
        try:
            offset = float(clock.get("max_offset_seconds"))
            if not 0 <= offset <= 3:
                errors.append("server_clock_offset_out_of_bounds")
        except (TypeError, ValueError):
            errors.append("server_clock_offset_invalid")

    offline = gate.get("offline_policy")
    if not isinstance(offline, dict) or offline.get("no_offline_grant_cache") is not True:
        errors.append("offline_limit_not_pinned")
    elif offline.get("pending_effects_fail_closed") is not True or offline.get("instant_revocation_promised") is not False:
        errors.append("offline_boundary_not_explicit")

    if fixture.get("schema") != FIXTURE_SCHEMA or fixture.get("status") != "VERIFIED":
        errors.append("parent_fixture_receipt_not_verified")
    if fixture.get("scope_policy") != "dedicated_test_environment":
        errors.append("parent_fixture_not_dedicated")
    if fixture.get("tenant_id") != private["tenant_id"] or fixture.get("project_id") != private["project_id"]:
        errors.append("parent_fixture_identity_mismatch")
    if gate.get("parent_principal_id") != fixture.get("parent_principal_id"):
        errors.append("parent_principal_pin_mismatch")
    return sorted(set(errors))


def validate_private(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema") != PRIVATE_SCHEMA:
        raise GateError("private_input_schema_mismatch")
    raw["api_base_url"] = validate_url(raw.get("api_base_url"))
    for field in ("tenant_id", "project_id", "other_project_id", "action", "resource_type", "resource_id"):
        raw[field] = require_id(raw.get(field), field)
    if raw["project_id"] == raw["other_project_id"]:
        raise GateError("cross_project_id_must_differ")
    if not isinstance(raw.get("parent_credential_file"), str) or not Path(raw["parent_credential_file"]).is_absolute():
        raise GateError("parent_credential_path_required")
    raw["authorize_context"] = scalar_map(raw.get("authorize_context", {}), "authorize_context")
    if raw["authorize_context"].get("project_id") != raw["project_id"]:
        raise GateError("authorize_context_project_mismatch")
    if any(key in raw["authorize_context"] for key in ("run_id", "instance_id", "tool_call_id", "probe_marker")):
        raise GateError("runner_correlation_values_must_be_generated")
    try:
        raw["expiry_ttl_seconds"] = int(raw["expiry_ttl_seconds"])
        raw["max_expiry_wait_seconds"] = int(raw["max_expiry_wait_seconds"])
        raw["revoke_slo_seconds"] = float(raw["revoke_slo_seconds"])
    except (KeyError, TypeError, ValueError):
        raise GateError("timing_input_invalid") from None
    if not 30 <= raw["expiry_ttl_seconds"] <= 600 or not raw["expiry_ttl_seconds"] <= raw["max_expiry_wait_seconds"] <= 900:
        raise GateError("expiry_window_out_of_bounds")
    if not 0 < raw["revoke_slo_seconds"] <= 30:
        raise GateError("revoke_slo_out_of_bounds")
    return raw


def load_inputs(private_path: str, gate_path: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    private = validate_private(read_json(private_path, private=True))
    gate = read_json(gate_path, private=True)
    fixture, _ = file_receipt(private.get("parent_fixture_receipt"), "parent_fixture")
    errors = validate_gate(gate, private, fixture)
    grants = fixture.get("parent_grants")
    if not isinstance(grants, list):
        errors.append("parent_grants_missing")
        grants = []
    parsed: list[dict[str, Any]] = []
    for raw in grants:
        try:
            parsed.append(validate_grant(raw, "parent_grant"))
        except GateError:
            continue
    delegate = next((g for g in parsed if g["action"] == "agents.delegate" and g["resource_type"] == "project" and g["resource_id"] == private["project_id"]), None)
    target = next((g for g in parsed if g["action"] == private["action"] and g["resource_type"] == private["resource_type"] and g["resource_id"] == private["resource_id"]), None)
    if delegate is None:
        errors.append("parent_agents_delegate_grant_missing")
    else:
        if delegate["conditions"].get("project_id") != private["project_id"]:
            errors.append("parent_delegate_project_condition_mismatch")
        if delegate["quota_max"] < 2:
            errors.append("parent_delegate_quota_below_two")
    if target is None:
        errors.append("parent_target_grant_missing")
    else:
        if target["conditions"].get("project_id") != private["project_id"]:
            errors.append("parent_target_project_condition_mismatch")
        if target["quota_max"] < 2:
            errors.append("parent_target_quota_below_two")
        for key, value in target["conditions"].items():
            if private["authorize_context"].get(key) != value:
                errors.append("authorize_context_missing_parent_condition_" + key)
    try:
        if parse_time(fixture.get("parent_expires_at"), "parent_expires_at") <= now_utc() + dt.timedelta(seconds=private["max_expiry_wait_seconds"] + 5):
            errors.append("parent_expires_before_test_window")
    except GateError as exc:
        errors.append(str(exc))
    return private, gate, fixture, sorted(set(errors))


def private_token(path: str) -> str:
    raw = read_bytes(path, private=True, limit=256)
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise GateError("parent_credential_not_ascii") from None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", token):
        raise GateError("parent_credential_format_invalid")
    return token


def write_json(path: Path, value: dict[str, Any]) -> None:
    temp = path.parent / ("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def new_output_dir(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise GateError("new_absolute_output_directory_required")
    try:
        parent_stat = os.stat(path.parent, follow_symlinks=False)
    except OSError:
        raise GateError("output_parent_unavailable") from None
    if not stat.S_ISDIR(parent_stat.st_mode) or (hasattr(os, "getuid") and parent_stat.st_uid != os.getuid()):
        raise GateError("output_parent_owner_or_type_invalid")
    os.mkdir(path, 0o700)
    current = os.lstat(path)
    if not stat.S_ISDIR(current.st_mode) or stat.S_IMODE(current.st_mode) & 0o077:
        raise GateError("output_directory_not_private")
    if hasattr(os, "getuid") and current.st_uid != os.getuid():
        raise GateError("output_directory_owner_mismatch")
    return path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTP:
    def __init__(self, base: str, timeout: float, journal: dict[str, Any], journal_path: Path):
        self.base, self.timeout = base.rstrip("/"), timeout
        self.journal, self.journal_path = journal, journal_path
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, name: str, method: str, path: str, token: str, payload: dict[str, Any] | None, expected: tuple[int, ...]) -> tuple[int, dict[str, Any] | None, float]:
        if not path.startswith("/") or "\n" in path or "\r" in path:
            raise RunError("api_path_invalid")
        body = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        record: dict[str, Any] = {"label": name, "method": method, "path": path, "state": "INTENT_DURABLE", "started_at_utc": iso(now_utc())}
        if body is not None:
            record["request_sha256"] = hashlib.sha256(body).hexdigest()
        self.journal["operations"].append(record)
        try:
            write_json(self.journal_path, self.journal)
        except OSError:
            record["state"] = "INTENT_NOT_DURABLE"
            raise RunError("journal_not_durable_before_request") from None
        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        start = time.monotonic()
        try:
            res = self.opener.open(req, timeout=self.timeout)
            status, raw = int(res.getcode()), res.read(2 * 1024 * 1024 + 1)
            res.close()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            try:
                raw = exc.read(2 * 1024 * 1024 + 1)
            except OSError:
                raw = b""
            finally:
                exc.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            record.update({"state": "OUTCOME_UNKNOWN" if method != "GET" else "READ_FAILED"})
            write_json(self.journal_path, self.journal)
            raise RunError("api_transport_failure", method != "GET") from None
        elapsed = time.monotonic() - start
        record.update({"state": "RESPONSE_RECEIVED", "http_status": status, "elapsed_ms": round(elapsed * 1000, 3)})
        try:
            write_json(self.journal_path, self.journal)
        except OSError:
            raise RunError("journal_write_failed_after_response", method != "GET") from None
        if status >= 500 and method != "GET":
            record["state"] = "OUTCOME_UNKNOWN"
            write_json(self.journal_path, self.journal)
            raise RunError("api_mutation_server_error", True)
        if status not in expected:
            return status, None, elapsed
        if not raw:
            return status, None, elapsed
        if len(raw) > 2 * 1024 * 1024:
            raise RunError("api_response_too_large", method != "GET" and status < 300)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise RunError("api_response_json_invalid", method != "GET" and status < 300) from None
        if not isinstance(data, dict):
            raise RunError("api_response_object_invalid", method != "GET" and status < 300)
        return status, data, elapsed


def key(run_id: str, label: str) -> str:
    value = f"t22:{run_id}:{label}"
    if not KEY_RE.fullmatch(value):
        raise GateError("idempotency_key_invalid")
    return value


def child_grant(grant: dict[str, Any], expires: dt.datetime, quota: int, resource_id: str | None = None) -> dict[str, Any]:
    return {
        "action": grant["action"],
        "resource_type": grant["resource_type"],
        "resource_id": resource_id or grant["resource_id"],
        "conditions": copy.deepcopy(grant["conditions"]),
        "expires_at": iso(expires),
        "quota_max": quota,
        "quota_window_seconds": grant["quota_window_seconds"],
    }


class Runner:
    def __init__(self, private: dict[str, Any], gate: dict[str, Any], fixture: dict[str, Any], token: str, out: Path):
        self.p, self.g, self.fixture, self.parent_token = private, gate, fixture, token
        self.run_id = uuid.uuid4().hex
        self.out = out
        self.report_path, self.journal_path = out / "run-report.json", out / "journal.json"
        self.report: dict[str, Any] = {
            "schema": SCHEMA, "run_id": self.run_id, "mode": "apply", "status": "RUNNING",
            "t22_acceptance_claim": "NOT_CLAIMED", "business_effect": "NOT_RUN", "offline_case": "NOT_RUN",
            "credentials_written_to_output": False,
            "source_pins": {"t22_source_commit": T22_COMMIT, "server_source_commit": gate["server"]["source_commit"],
                            "server_source_tree": gate["server"]["source_tree"], "server_binary_sha256": gate["server"]["binary_sha256"]},
            "fixture": {"tenant_id": private["tenant_id"], "project_id": private["project_id"],
                        "parent_principal_id": fixture["parent_principal_id"],
                        "parent_fixture_receipt_sha256": private["parent_fixture_receipt"]["sha256"]},
            "cases": [], "durable_resources": [],
            "cleanup": {"delete_supported": False, "revocation_is_tombstone": True, "unresolved_resources": []},
            "api_target": "redacted",
        }
        self.journal: dict[str, Any] = {
            "schema": "t22.acceptance-journal.v1", "run_id": self.run_id,
            "created_at_utc": iso(now_utc()), "source_commit": T22_COMMIT,
            "fixture": self.report["fixture"], "operations": [],
            "idempotency_keys": {name: key(self.run_id, name) for name in (
                "main-auth", "main-create", "overscope-auth", "overscope-create",
                "grandchild-auth", "grandchild-create", "expiry-auth", "expiry-create",
            )},
            "note": "No credential, raw response body, or Authorization header is persisted.",
        }
        write_json(self.journal_path, self.journal)
        write_json(self.report_path, self.report)
        self.http = HTTP(private["api_base_url"], float(private.get("request_timeout_seconds", 10)), self.journal, self.journal_path)
        grants = [validate_grant(g, "parent_grant") for g in fixture["parent_grants"]]
        self.delegate = next(g for g in grants if g["action"] == "agents.delegate" and g["resource_type"] == "project" and g["resource_id"] == private["project_id"])
        self.target = next(g for g in grants if g["action"] == private["action"] and g["resource_type"] == private["resource_type"] and g["resource_id"] == private["resource_id"])
        self.root_relations: list[dict[str, Any]] = []
        self.tokens: list[str] = []
        self.markers: list[str] = []
        self.correlations: dict[str, dict[str, str]] = {}

    def add_case(self, name: str, status: str, **details: Any) -> None:
        self.report["cases"].append({"id": name, "status": status, **details})
        write_json(self.report_path, self.report)

    def verify_returned_grants(self, expected: list[dict[str, Any]], returned: Any) -> list[dict[str, Any]]:
        if not isinstance(returned, list) or len(returned) != len(expected):
            raise RunError("delegation_returned_grant_count_mismatch")
        summaries: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for wanted in expected:
            identity = (wanted["action"], wanted["resource_type"], wanted["resource_id"])
            matches = [
                actual for actual in returned
                if isinstance(actual, dict) and
                (actual.get("action"), actual.get("resource_type"), actual.get("resource_id")) == identity
            ]
            if len(matches) != 1 or identity in seen:
                raise RunError("delegation_returned_grant_identity_mismatch")
            actual = matches[0]
            seen.add(identity)
            actual_id = actual.get("id")
            if not isinstance(actual_id, str) or not actual_id:
                raise RunError("delegation_returned_grant_id_missing")
            actual_max, actual_window = actual.get("quota_max"), actual.get("quota_window_seconds")
            if isinstance(actual_max, bool) or not isinstance(actual_max, int) or actual_max != wanted["quota_max"]:
                raise RunError("delegation_effective_quota_max_mismatch")
            if isinstance(actual_window, bool) or not isinstance(actual_window, int) or actual_window != wanted["quota_window_seconds"]:
                raise RunError("delegation_effective_quota_window_mismatch")
            actual_conditions = actual.get("conditions", {})
            wanted_conditions = wanted.get("conditions", {})
            if (
                not isinstance(actual_conditions, dict) or
                json.dumps(actual_conditions, sort_keys=True, separators=(",", ":")) !=
                json.dumps(wanted_conditions, sort_keys=True, separators=(",", ":"))
            ):
                raise RunError("delegation_effective_conditions_mismatch")
            actual_expiry = parse_time(actual.get("expires_at"), "returned_grant_expires_at")
            wanted_expiry = parse_time(wanted.get("expires_at"), "requested_grant_expires_at")
            if actual_expiry != wanted_expiry:
                raise RunError("delegation_effective_expiry_mismatch")
            summaries.append({
                "grant_id": actual_id,
                "action": identity[0], "resource_type": identity[1], "resource_id": identity[2],
                "quota_max": actual_max, "quota_window_seconds": actual_window,
                "expires_at": iso(actual_expiry), "condition_keys": sorted(actual_conditions),
            })
        return summaries

    def create(self, label: str, parent_token: str, parent_id: str, expires: dt.datetime, grants: list[dict[str, Any]], auth_key: str, create_key: str) -> tuple[dict[str, Any], str]:
        request = {
            "name": f"t22-{self.run_id[:10]}-{label}",
            "project_id": self.p["project_id"],
            "expires_at": iso(expires),
            "grants": grants,
            "authorization_idempotency_key": self.journal["idempotency_keys"][auth_key],
            "idempotency_key": self.journal["idempotency_keys"][create_key],
        }
        status, data, elapsed = self.http.call("create_" + label, "POST", "/admin/v1/agent/delegations", parent_token, request, (201,))
        if status == 201 and not data:
            raise RunError("delegation_create_response_unreconciled", True)
        if status != 201:
            raise RunError("delegation_create_rejected")
        relation, credential = data.get("delegation"), data.get("credential")
        if not isinstance(relation, dict) or not isinstance(credential, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", credential):
            raise RunError("delegation_create_response_unreconciled", True)
        public = {
            "delegation_id": require_id(relation.get("id"), "delegation_id"),
            "parent_principal_id": require_id(relation.get("parent_principal_id"), "parent_principal_id"),
            "child_principal_id": require_id(relation.get("child_principal_id"), "child_principal_id"),
            "project_id": require_id(relation.get("project_id"), "created_project_id"),
            "expires_at": relation.get("expires_at"), "status": relation.get("status"),
            "credential_persisted": False, "create_elapsed_ms": round(elapsed * 1000, 3),
        }
        if public["parent_principal_id"] != parent_id or public["project_id"] != self.p["project_id"]:
            raise RunError("delegation_identity_mismatch")
        if parent_id == self.fixture["parent_principal_id"]:
            self.root_relations.append(public)
        self.journal["operations"][-1]["public_result"] = public
        write_json(self.journal_path, self.journal)
        self.report["durable_resources"].append(public.copy())
        write_json(self.report_path, self.report)
        self.tokens.append(credential)
        if public["status"] != "active" or parse_time(public["expires_at"], "returned_delegation_expires_at") != parse_time(iso(expires), "requested_delegation_expires_at"):
            raise RunError("delegation_effective_identity_or_expiry_mismatch")
        effective_grants = self.verify_returned_grants(grants, data.get("grants"))
        public["effective_grants"] = effective_grants
        self.journal["operations"][-1]["public_result"] = public
        write_json(self.journal_path, self.journal)
        self.report["durable_resources"][-1].update({"effective_grants": effective_grants})
        write_json(self.report_path, self.report)
        return public, credential

    def authorize(self, label: str, token: str, project: str | None = None) -> tuple[int, dict[str, Any] | None, dict[str, str]]:
        correlation = {
            "run_id": f"t22-{self.run_id[:12]}-{label}",
            "instance_id": f"t22-instance-{self.run_id[:12]}",
            "tool_call_id": f"t22-tool-{label}-{self.run_id[:8]}",
        }
        marker = f"t22-marker-{self.run_id}-{label}"
        context = copy.deepcopy(self.p["authorize_context"])
        context["project_id"] = project or self.p["project_id"]
        context.update(correlation)
        context["probe_marker"] = marker
        self.markers.append(marker)
        request_key = key(self.run_id, "authorize-" + label)
        body = {
            "action": self.p["action"], "resource_type": self.p["resource_type"],
            "resource_id": self.p["resource_id"], "context": context,
            "idempotency_key": request_key,
        }
        status, data, _ = self.http.call("authorize_" + label, "POST", "/admin/v1/agent/authorize", token, body, (200, 401))
        observed = {**correlation, "authorization_idempotency_key": request_key}
        self.correlations[label] = observed
        if status == 401:
            return status, None, observed
        if not data or not isinstance(data.get("allowed"), bool) or not isinstance(data.get("reason"), str):
            raise RunError("authorization_response_invalid")
        self.journal["operations"][-1]["public_result"] = {
            "allowed": data["allowed"], "reason": data["reason"], "principal_id": data.get("principal_id"),
            "action": data.get("action"), "resource_type": data.get("resource_type"),
            "resource_id": data.get("resource_id"), "idempotency_key": data.get("idempotency_key"),
        }
        write_json(self.journal_path, self.journal)
        return status, data, observed

    def require_target_decision(self, decision: Any, principal_id: str, allowed: bool, reason: str | None = None) -> None:
        if not isinstance(decision, dict):
            raise RunError("authorization_decision_missing")
        if decision.get("principal_id") != principal_id:
            raise RunError("authorization_principal_mismatch")
        if decision.get("action") != self.p["action"] or decision.get("resource_type") != self.p["resource_type"] or decision.get("resource_id") != self.p["resource_id"]:
            raise RunError("authorization_target_tuple_mismatch")
        if decision.get("allowed") is not allowed:
            raise RunError("authorization_allowed_mismatch")
        if reason is not None and decision.get("reason") != reason:
            raise RunError("authorization_reason_mismatch")

    def calls(self, token: str, relation_id: str) -> list[dict[str, Any]]:
        path = "/admin/v1/agent/delegations/" + urllib.parse.quote(relation_id, safe="") + "/calls?limit=200"
        status, data, _ = self.http.call("list_calls_" + relation_id, "GET", path, token, None, (200,))
        if status != 200 or not data or not isinstance(data.get("items"), list):
            raise RunError("investigation_response_invalid")
        raw = json.dumps(data, sort_keys=True)
        for marker in self.markers:
            if marker in raw:
                raise RunError("investigation_raw_context_leak")
        for token_value in [self.parent_token, *self.tokens]:
            if token_value and token_value in raw:
                raise RunError("investigation_credential_leak")
        rows = []
        for item in data["items"]:
            if not isinstance(item, dict) or any(SENSITIVE_KEY_RE.search(str(k)) for k in item):
                raise RunError("investigation_sensitive_field_present")
            rows.append({field: item.get(field) for field in CALL_FIELDS if field in item})
        self.journal["operations"][-1]["public_result"] = {"row_count": len(rows), "raw_marker_or_credential_leak": False}
        write_json(self.journal_path, self.journal)
        return rows

    def revoke(self, relation: dict[str, Any], parent_token: str, label: str) -> tuple[bool, float]:
        path = "/admin/v1/agent/delegations/" + urllib.parse.quote(relation["delegation_id"], safe="") + "/revoke"
        status, _, elapsed = self.http.call(label, "POST", path, parent_token, {}, (204, 404))
        ok = status == 204
        self.journal["operations"][-1]["public_result"] = {"revoked": ok, "http_status": status}
        write_json(self.journal_path, self.journal)
        relation["revoked"] = ok
        relation["revoke_http_status"] = status
        for item in self.report["durable_resources"]:
            if item.get("delegation_id") == relation.get("delegation_id"):
                item["revoked"] = ok
        write_json(self.report_path, self.report)
        return ok, elapsed

    def execute(self) -> dict[str, Any]:
        now = now_utc()
        main_expiry = min(now + dt.timedelta(seconds=600), self.delegate["expires_at"], self.target["expires_at"])
        ttl = self.p["expiry_ttl_seconds"]
        if main_expiry <= now + dt.timedelta(seconds=ttl + 10):
            raise GateError("parent_grants_too_close_to_expiry")
        main_grants = [
            child_grant(self.delegate, main_expiry, min(self.delegate["quota_max"], 3)),
            child_grant(self.target, main_expiry, min(self.target["quota_max"], 2)),
        ]
        main, main_token = self.create("main", self.parent_token, self.fixture["parent_principal_id"], main_expiry, main_grants, "main-auth", "main-create")
        self.add_case("valid_parent_child_delegation", "PASS", delegation_id=main["delegation_id"], child_principal_id=main["child_principal_id"])

        # Try to use the child's delegation grant to widen its own target resource.
        # The failed create consumes one child agents.delegate authorization.
        wider = self.p["resource_id"] + "-outside"
        if len(wider) > 256:
            raise GateError("resource_id_too_long_for_scope_probe")
        overscope = {
            "name": f"t22-{self.run_id[:10]}-overscope",
            "project_id": self.p["project_id"],
            "expires_at": iso(main_expiry),
            "grants": [child_grant(self.target, main_expiry, 1, wider)],
            "authorization_idempotency_key": self.journal["idempotency_keys"]["overscope-auth"],
            "idempotency_key": self.journal["idempotency_keys"]["overscope-create"],
        }
        status, data, elapsed = self.http.call(
            "child_resource_expansion_probe", "POST", "/admin/v1/agent/delegations",
            main_token, overscope, (400, 201),
        )
        if status == 201 and not data:
            raise RunError("unexpected_child_delegation_unreconciled", True)
        if status == 201 and data:
            relation = data.get("delegation")
            if not isinstance(relation, dict) or not isinstance(relation.get("id"), str):
                raise RunError("unexpected_child_delegation_unreconciled", True)
            unexpected = {
                "delegation_id": relation["id"],
                "parent_principal_id": relation.get("parent_principal_id"),
                "child_principal_id": relation.get("child_principal_id"),
                "project_id": relation.get("project_id"),
                "credential_persisted": False,
                "unexpected_scope_expansion": True,
            }
            self.report["durable_resources"].append(unexpected)
            credential = data.get("credential")
            if isinstance(credential, str):
                self.tokens.append(credential)
            self.add_case("child_cannot_widen_resource_grant", "FAIL", http_status=status, unexpected_delegation_id=relation["id"])
            raise RunError("child_created_wider_delegation")
        error = data.get("error") if isinstance(data, dict) else None
        if status != 400 or not isinstance(error, dict):
            raise RunError("child_scope_expansion_probe_status_unexpected")
        if error.get("code") != "invalid_request" or error.get("message") != "delegation exceeds its parent scope":
            raise RunError("child_scope_expansion_probe_not_typed_parent_scope_error")
        self.journal["operations"][-1]["public_result"] = {
            "http_status": status, "error_code": error["code"],
            "error_reason": "delegation_exceeds_parent_scope",
        }
        write_json(self.journal_path, self.journal)
        self.add_case(
            "child_cannot_widen_resource_grant", "PASS", http_status=status,
            error_code=error["code"], reason="delegation_exceeds_parent_scope",
            elapsed_ms=round(elapsed * 1000, 3),
        )

        grand_expiry = min(main_expiry, now_utc() + dt.timedelta(seconds=ttl + 30))
        grand, grand_token = self.create(
            "grandchild", main_token, main["child_principal_id"], grand_expiry,
            [child_grant(self.target, grand_expiry, 1)], "grandchild-auth", "grandchild-create",
        )
        self.report["durable_resources"][-1]["parent_delegation_id"] = main["delegation_id"]
        write_json(self.report_path, self.report)
        self.add_case("nested_child_delegation", "PASS", delegation_id=grand["delegation_id"], child_principal_id=grand["child_principal_id"], parent_delegation_id=main["delegation_id"])

        status, decision, corr = self.authorize("cross-project", grand_token, self.p["other_project_id"])
        if status != 200:
            raise RunError("cross_project_authorization_status_unexpected")
        self.require_target_decision(decision, grand["child_principal_id"], False)
        self.add_case("cross_project_denied", "PASS", allowed=False, reason=decision.get("reason"), correlation=corr)

        status, decision, corr = self.authorize("grandchild-allow", grand_token)
        if status != 200:
            raise RunError("grandchild_authorization_status_unexpected")
        self.require_target_decision(decision, grand["child_principal_id"], True, "allowed")
        self.add_case("grandchild_authorized", "PASS", allowed=True, reason=decision.get("reason"), correlation=corr)

        grand_target_grants = [
            item for item in grand["effective_grants"]
            if item["action"] == self.p["action"] and item["resource_type"] == self.p["resource_type"] and item["resource_id"] == self.p["resource_id"]
        ]
        if len(grand_target_grants) != 1:
            raise RunError("grandchild_target_grant_not_unique")
        quota_grant = grand_target_grants[0]
        if quota_grant["quota_max"] != 1 or quota_grant["quota_window_seconds"] != self.target["quota_window_seconds"]:
            raise RunError("grandchild_quota_ceiling_mismatch")

        status, decision, corr = self.authorize("grandchild-quota", grand_token)
        if status != 200:
            raise RunError("grandchild_quota_status_unexpected")
        self.require_target_decision(decision, grand["child_principal_id"], False, "quota_exceeded")
        self.add_case(
            "grandchild_quota_exhaustion", "PASS", allowed=False, reason=decision.get("reason"),
            quota_max=quota_grant["quota_max"], quota_window_seconds=quota_grant["quota_window_seconds"],
            observed_sequence={"allowed_attempts_before_quota_exceeded": 1, "quota_exceeded_attempts": 1},
            principal_id=grand["child_principal_id"], action=self.p["action"],
            resource_type=self.p["resource_type"], resource_id=self.p["resource_id"], correlation=corr,
        )

        parent_rows = self.calls(self.parent_token, main["delegation_id"])
        child_rows = self.calls(main_token, grand["delegation_id"])
        overscope_auth_key = self.journal["idempotency_keys"]["overscope-auth"]
        scope_audit = [
            row for row in parent_rows
            if row.get("authorization_idempotency_key") == overscope_auth_key
        ]
        if len(scope_audit) != 1:
            raise RunError("child_scope_probe_authorization_audit_not_unique")
        scope_row = scope_audit[0]
        if (
            scope_row.get("calling_principal_id") != main["child_principal_id"] or
            scope_row.get("action") != "agents.delegate" or
            scope_row.get("resource_type") != "project" or
            scope_row.get("resource_id") != self.p["project_id"] or
            scope_row.get("project_id") != self.p["project_id"] or
            scope_row.get("allowed") is not True or
            scope_row.get("reason") != "allowed"
        ):
            raise RunError("child_scope_probe_authorization_audit_mismatch")

        expected_calls = {
            "cross-project": False,
            "grandchild-allow": True,
            "grandchild-quota": False,
        }
        verified_rows = 0
        for label, expected_allowed in expected_calls.items():
            value = self.correlations[label]
            triple = (value["run_id"], value["instance_id"], value["tool_call_id"])
            for view_name, rows, relation_id in (
                ("parent", parent_rows, main["delegation_id"]),
                ("child", child_rows, grand["delegation_id"]),
            ):
                matches = [
                    row for row in rows
                    if (row.get("run_id"), row.get("instance_id"), row.get("tool_call_id")) == triple
                ]
                if len(matches) != 1:
                    raise RunError("investigation_correlation_row_count_mismatch")
                row = matches[0]
                if (
                    row.get("delegation_id") != relation_id or
                    row.get("calling_principal_id") != grand["child_principal_id"] or
                    row.get("project_id") != self.p["project_id"] or
                    row.get("action") != self.p["action"] or
                    row.get("resource_type") != self.p["resource_type"] or
                    row.get("resource_id") != self.p["resource_id"] or
                    row.get("authorization_idempotency_key") != value["authorization_idempotency_key"] or
                    row.get("allowed") is not expected_allowed
                ):
                    raise RunError("investigation_correlation_row_mismatch")
                if label == "grandchild-quota" and row.get("reason") != "quota_exceeded":
                    raise RunError("investigation_quota_reason_mismatch")
                verified_rows += 1
        self.add_case(
            "parent_child_investigation_redacted", "PASS",
            parent_rows=len(parent_rows), child_rows=len(child_rows),
            exact_correlations=len(expected_calls), unique_verified_rows=verified_rows,
            scope_rejection_audit={
                "authorization_idempotency_key": overscope_auth_key,
                "action": scope_row["action"], "resource_type": scope_row["resource_type"],
                "resource_id": scope_row["resource_id"], "allowed": scope_row["allowed"],
                "reason": scope_row["reason"],
                "followed_by_typed_scope_error": True,
            },
            marker_or_credential_leak=False,
        )

        start = time.monotonic()
        revoked, revoke_time = self.revoke(main, self.parent_token, "revoke_parent_child")
        if not revoked:
            raise RunError("parent_revoke_not_confirmed")
        end_revoke = start + revoke_time
        status, decision, corr = self.authorize("after-revoke", grand_token)
        propagation_ms = round((time.monotonic() - end_revoke) * 1000, 3)
        if status not in (200, 401) or (decision and decision.get("allowed") is True):
            raise RunError("descendant_revoke_not_propagated")
        if propagation_ms > self.p["revoke_slo_seconds"] * 1000:
            raise RunError("revoke_propagation_slo_exceeded")
        self.report["durable_resources"][-1]["revoked_by_parent_cascade"] = True
        self.add_case("descendant_revoke_propagation", "PASS", http_status=status, allowed=False, observed_ms=propagation_ms, configured_slo_ms=round(self.p["revoke_slo_seconds"] * 1000, 3), correlation=corr)

        # A separate direct child is left expired as an auditable tombstone.
        ttl_expiry = min(now_utc() + dt.timedelta(seconds=ttl), self.delegate["expires_at"], self.target["expires_at"])
        ttl_child, ttl_token = self.create(
            "expiry", self.parent_token, self.fixture["parent_principal_id"], ttl_expiry,
            [child_grant(self.target, ttl_expiry, 1)], "expiry-auth", "expiry-create",
        )
        self.report["durable_resources"][-1]["ttl_probe"] = True
        write_json(self.report_path, self.report)
        expiry_at = parse_time(ttl_child["expires_at"], "child_expiry")
        wait = max(0.0, (expiry_at - now_utc()).total_seconds()) + float(self.g["clock"]["max_offset_seconds"]) + 0.5
        if wait > self.p["max_expiry_wait_seconds"]:
            raise GateError("ttl_wait_exceeds_configured_maximum")
        self.journal["ttl_wait"] = {"expires_at": ttl_child["expires_at"], "planned_wait_seconds": round(wait, 3)}
        write_json(self.journal_path, self.journal)
        time.sleep(wait)
        probe_at = now_utc()
        status, decision, corr = self.authorize("after-expiry", ttl_token)
        expired_ms = round((probe_at - expiry_at).total_seconds() * 1000, 3)
        if status not in (200, 401) or (decision and decision.get("allowed") is True) or expired_ms < 0:
            raise RunError("child_expiry_not_enforced")
        self.add_case("child_ttl_enforcement", "PASS", http_status=status, allowed=False, observed_after_expiry_ms=expired_ms, correlation=corr)
        self.report["cleanup"]["unresolved_resources"] = [{
            "delegation_id": ttl_child["delegation_id"], "child_principal_id": ttl_child["child_principal_id"],
            "state": "EXPIRED_RETAINED_NO_DELETE_API",
        }]
        self.report["status"] = "CONTROL_PLANE_AUTHORIZATION_PASS_EFFECT_AND_OFFLINE_NOT_RUN"
        self.report["limits"] = [
            "This runner invokes authorization only; it does not perform or attest a T17 business mutation.",
            "Offline outage behavior is not exercised by this runner.",
            "Revoked/expired relations and investigation rows are durable; no delete API is present.",
            "Do not claim T22.accept from this report without the real child effect chain and explicit offline-limit evidence.",
        ]
        self.report["finished_at_utc"] = iso(now_utc())
        write_json(self.report_path, self.report)
        return self.report


def plan(blockers: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "mode": "plan", "status": "PLAN_ONLY_NO_NETWORK",
        "network_calls": 0, "database_calls": 0, "migration_actions": 0, "business_effects": 0,
        "t22_acceptance_claim": "NOT_CLAIMED", "t22_source_commit": T22_COMMIT,
        "cases": [
            "parent creates a bounded child in one dedicated project",
            "child receives allowed agents.delegate audit then typed out-of-parent-scope create error",
            "child creates a narrower grandchild; returned grant quota/window values are checked",
            "cross-project target authorization is denied; one-unit target quota allows once then returns quota_exceeded",
            "parent revoke denies the descendant; short TTL denial is measured",
            "parent and child views each contain exactly one matching investigation row per expected correlation",
            "parent and child investigation views omit raw context markers and credentials",
        ],
        "not_executed": ["T15 approval/claim", "T17 business mutation", "offline outage"],
        "blockers": blockers or [],
    }


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan-first T22 delegation acceptance runner")
    parser.add_argument("--apply", action="store_true", help="run only after root-authored runtime gates pass")
    parser.add_argument("--gate", help="mode-0600 root runtime/migration gate JSON")
    parser.add_argument("--private-input", help="mode-0600 fixture and credential-path JSON")
    parser.add_argument("--out-dir", help="new absolute output directory; created mode 0700")
    parser.add_argument("--request-timeout-seconds", type=float, default=10.0)
    args = parser.parse_args()
    if not args.apply:
        emit(plan())
        return 0
    if not args.gate or not args.private_input or not args.out_dir or not 1 <= args.request_timeout_seconds <= 30:
        emit(plan(["apply_requires_gate_private_input_output_and_bounded_timeout"]))
        return 2
    try:
        private, gate, fixture, blockers = load_inputs(args.private_input, args.gate)
        if blockers:
            emit(plan(blockers))
            return 3
        token = private_token(private["parent_credential_file"])
        out = new_output_dir(args.out_dir)
        private["request_timeout_seconds"] = args.request_timeout_seconds
        runner = Runner(private, gate, fixture, token, out)
        try:
            report = runner.execute()
        except (GateError, RunError, OSError, ValueError) as exc:
            code = exc.code if isinstance(exc, RunError) else ("journal_or_output_error" if isinstance(exc, OSError) else "runner_value_error")
            last_op = runner.journal["operations"][-1] if runner.journal["operations"] else {}
            unknown = isinstance(exc, RunError) and exc.unknown_outcome
            if isinstance(exc, OSError) and last_op.get("method") != "GET" and last_op.get("state") in ("INTENT_DURABLE", "RESPONSE_RECEIVED", "OUTCOME_UNKNOWN"):
                unknown = True
            runner.report.update({"status": "PARTIAL_OR_UNKNOWN", "fatal_code": code, "finished_at_utc": iso(now_utc())})
            if unknown:
                runner.report["unknown_mutation_outcome"] = True
                runner.report["cleanup"]["unresolved_resources"].append({"state": "UNKNOWN_MUTATION_OUTCOME_REQUIRES_ROOT_RECONCILIATION"})
            for relation in (() if unknown else reversed(runner.root_relations)):
                if relation.get("revoked") is True:
                    continue
                try:
                    did_revoke, _ = runner.revoke(relation, token, "failure_cleanup_revoke")
                    if not did_revoke:
                        runner.report["cleanup"]["unresolved_resources"].append({"delegation_id": relation.get("delegation_id"), "state": "REVOCATION_NOT_CONFIRMED"})
                except (GateError, RunError):
                    runner.report["cleanup"]["unresolved_resources"].append({"delegation_id": relation.get("delegation_id"), "state": "REVOCATION_OUTCOME_UNKNOWN"})
            try:
                write_json(runner.report_path, runner.report)
            except OSError:
                runner.report["report_write_failed"] = True
            emit(runner.report)
            return 4
        emit(report)
        return 0
    except GateError as exc:
        emit(plan([str(exc)]))
        return 3
    except (OSError, ValueError):
        emit(plan(["preflight_or_private_output_error"]))
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
