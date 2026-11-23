#!/usr/bin/env python3
"""Inventory and lint JJDGuard database and offline-upgrade steps."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "deploy/migrations"
BASELINE = ROOT / "deploy/upgrade/migration-lint-baseline.json"
INVENTORY = ROOT / "docs/operations/upgrade-step-inventory.json"
RISKS = ROOT / "docs/operations/migration-risk-register.json"
BIG_TABLES = {
    "request_logs", "content_logs", "access_content_logs", "security_events",
    "audit_operations", "audit_chain", "tool_call_logs", "alert_groups",
    "evidence_run_request_index", "retained_artifacts", "outbox_events",
}
REQUIRED_FIELDS = {
    "step_name", "version", "mutates_data", "starts_transaction", "lock_level",
    "full_table_scan", "full_table_rewrite", "creates_index", "row_function",
    "network_dependency", "idempotent", "interrupt_resumable", "has_timeout",
    "has_progress", "blocks_service_start", "complexity", "disk_wal_risk",
    "risk_level", "tests",
}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def migration_key(path: pathlib.Path) -> tuple[int, str]:
    match = re.match(r"([0-9]{3,})_", path.name)
    if not match:
        return (2**63 - 1, path.name)
    return (int(match.group(1)), path.name)


def sql_files() -> list[pathlib.Path]:
    return sorted(
        (path for path in MIGRATIONS.glob("*_*.sql") if re.fullmatch(r"[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql", path.name)),
        key=migration_key,
    )


def shell_files() -> list[pathlib.Path]:
    roots = [
        ROOT / "deploy/docker-compose", ROOT / "deploy/offline-installer",
        ROOT / "deploy/lib", ROOT / "deploy/release",
    ]
    result: list[pathlib.Path] = []
    for directory in roots:
        result.extend(path for path in directory.glob("*.sh") if path.is_file())
    return sorted(set(result))


def table_mentions(text: str) -> set[str]:
    lower = text.lower()
    return {table for table in BIG_TABLES if re.search(r"\b" + re.escape(table) + r"\b", lower)}


def without_function_definitions(text: str) -> str:
    text = re.sub(r"(?is)/[*].*?[*]/", "", text)
    text = re.sub(r"(?m)--.*$", "", text)
    return re.sub(
        r"(?is)create\s+(?:or\s+replace\s+)?function\b.*?\$\$\s*;",
        "",
        text,
    )


# 迁移文件头部可用 "-- governance-test: <路径>[::<用例名>]" 声明额外的验证用例（如真库测试），登记进清单。
DECLARED_TEST = re.compile(r"(?m)^--\s*governance-test:\s*(\S+)\s*$")


def sql_inventory(path: pathlib.Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    operational = without_function_definitions(text)
    lower = operational.lower()
    tables = table_mentions(operational)
    bounded_key_function = bool(
        re.search(r"(?i)where\s+rl[.]tenant_id\s*=\s*p_tenant_id", operational)
        and re.search(r"(?i)rl[.](request_id|id)\s*=\s*p_request_id", operational)
    )
    data_dml = bool(re.search(r"(?im)^\s*(update|delete\s+from|insert\s+into)\s+", operational))
    creates_index = bool(re.search(r"(?i)create\s+(unique\s+)?index", operational))
    full_scan = not bounded_key_function and bool(
        re.search(r"(?is)\bupdate\s+(request_logs|content_logs|access_content_logs|security_events|audit_operations|evidence_run_request_index)\b", operational)
        or re.search(r"(?is)\bfrom\s+(request_logs|content_logs|access_content_logs|security_events)\b", operational)
    )
    rewrite = bool(re.search(r"(?is)alter\s+table.+alter\s+column.+\btype\b|set\s+not\s+null", operational))
    row_function = bool(re.search(r"(?is)select\s+[a-z_][a-z0-9_]*\s*\([^;]+\)\s+from\s+", operational))
    concurrent = "index concurrently" in lower
    background = "migration_backfill_tasks" in lower
    high = row_function or rewrite or (data_dml and full_scan) or (creates_index and bool(tables) and not concurrent)
    medium = data_dml or creates_index or bool(re.search(r"(?i)alter\s+table", text))
    risk = "MAINTENANCE_REQUIRED" if high else ("ONLINE_WITH_BACKFILL" if background else ("SAFE_ONLINE" if not medium else "ONLINE_WITH_BACKFILL"))
    # CREATE/DROP TRIGGER 在表上取 SHARE ROW EXCLUSIVE，比并发建索引和普通 DML 的锁都强（会挡住写入）。
    trigger_ddl = bool(re.search(r"(?i)\b(create\s+(or\s+replace\s+)?(constraint\s+)?trigger|drop\s+trigger)\b", operational))
    # 触发器所在的表（ON <表>）都列进清单，不限于大表：建删触发器会挡住这些表的写入。
    trigger_tables = set(re.findall(
        r"(?is)\b(?:create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger|drop\s+trigger(?:\s+if\s+exists)?)\s+\w+.*?\bon\s+([a-z_][a-z0-9_]*)",
        operational))
    tables = tables | {table.lower() for table in trigger_tables}
    lock = "ACCESS EXCLUSIVE possible" if rewrite or re.search(r"(?i)alter\s+table", text) else (
        "SHARE ROW EXCLUSIVE" if trigger_ddl else (
            "SHARE UPDATE EXCLUSIVE" if concurrent else ("ROW EXCLUSIVE" if data_dml else "none/metadata")
        )
    )
    return {
        "step_name": path.name,
        "path": str(path.relative_to(ROOT)),
        "version": str(migration_key(path)[0]),
        "mutates_data": data_dml,
        "starts_transaction": bool(re.search(r"(?im)^\s*begin\s*;", text)),
        "lock_level": lock,
        "full_table_scan": full_scan,
        "full_table_rewrite": rewrite,
        "creates_index": creates_index,
        "row_function": row_function,
        "network_dependency": False,
        "idempotent": bool(re.search(r"(?i)if\s+not\s+exists|on\s+conflict|create\s+or\s+replace", text)) and "offset " not in lower,
        "interrupt_resumable": background or not (data_dml and full_scan),
        "has_timeout": True,
        "has_progress": True,
        "blocks_service_start": not background,
        "complexity": "O(rows)" if full_scan else ("O(rows log rows)" if creates_index else "O(1)/catalog"),
        "disk_wal_risk": "high" if data_dml and full_scan else ("medium" if creates_index else "low"),
        "risk_level": risk,
        "tests": ["deploy/tests/test_migration_runner.sh"] + DECLARED_TEST.findall(text),
        "sha256": digest(path),
        "tables": sorted(tables),
        "requires_write_pause": trigger_ddl,
        "operator_note": ("建删触发器在所列表上取 SHARE ROW EXCLUSIVE，会挡住这些表的写入；在停写入的维护窗口执行"
                          if trigger_ddl else ""),
    }


def shell_inventory(path: pathlib.Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lower = text.lower()
    mutates = bool(re.search(r"(?m)^\s*(cp|mv|install|docker\s+(load|pull)|.*compose.*\s(up|down|stop))\b", text))
    network = bool(re.search(r"\b(curl|wget|git\s+(fetch|clone|ls-remote)|docker\s+pull)\b", lower))
    timeout = bool(re.search(r"\b(timeout|deadline|max_attempt|retries|seconds\s*[<>])\b", lower))
    progress = bool(re.search(r"\b(echo|printf|log|say|progress|heartbeat)\b", lower))
    loop = bool(re.search(r"(?m)^\s*(while|until)\b", text))
    risk = "MAINTENANCE_REQUIRED" if mutates and (loop and not timeout) else ("ONLINE_WITH_BACKFILL" if mutates else "SAFE_ONLINE")
    return {
        "step_name": path.name,
        "path": str(path.relative_to(ROOT)),
        "version": "runtime",
        "mutates_data": mutates,
        "starts_transaction": False,
        "lock_level": "service/filesystem" if mutates else "none",
        "full_table_scan": False,
        "full_table_rewrite": False,
        "creates_index": False,
        "row_function": False,
        "network_dependency": network,
        "idempotent": "if " in lower or "exists" in lower,
        "interrupt_resumable": bool(re.search(r"partial|pending|resume|state|checkpoint", lower)),
        "has_timeout": timeout,
        "has_progress": progress,
        "blocks_service_start": "install" in path.name or "upgrade" in path.name,
        "complexity": "O(bytes/services)" if mutates else "O(1)",
        "disk_wal_risk": "medium" if re.search(r"backup|image|model|gguf|copy|load", lower) else "low",
        "risk_level": risk,
        "tests": ["deploy/lib/acceptance-gate.sh"],
        "sha256": digest(path),
    }


def inventory() -> list[dict[str, object]]:
    return [sql_inventory(path) for path in sql_files()] + [shell_inventory(path) for path in shell_files()]


def sql_findings(path: pathlib.Path) -> list[str]:
    text = without_function_definitions(path.read_text(encoding="utf-8"))
    lower = text.lower()
    tables = table_mentions(text)
    findings: set[str] = set()
    dml_text = ";".join(
        statement for statement in text.split(";")
        if not re.match(r"(?is)^\s*(create|alter|drop|grant|revoke)\b", statement)
    ) + ";"
    for match in re.finditer(r"(?is)\b(update\s+[a-z_][a-z0-9_]*|delete\s+from\s+[a-z_][a-z0-9_]*)\b(.*?);", dml_text):
        statement = match.group(0)
        if not re.search(r"(?i)\bwhere\b", statement):
            findings.add("unbounded_update_delete")
    if re.search(r"(?is)select\s+[a-z_][a-z0-9_]*\s*\([^;]+\)\s+from\s+", text):
        findings.add("row_function_backfill")
    if re.search(r"(?i)\boffset\s+([1-9]|[:$])", text):
        findings.add("offset_pagination")
    if (re.search(r"(?im)^\s*begin\s*;", text)
            and re.search(r"(?im)^\s*(update|delete\s+from)\s+", text)
            and table_mentions(text)):
        findings.add("large_dml_transaction")
    if (re.search(r"(?i)create\s+(unique\s+)?index(?!\s+concurrently)", text)
            and tables):
        findings.add("nonconcurrent_large_index")
    if re.search(r"(?is)alter\s+table.+(alter\s+column.+\btype\b|set\s+not\s+null)", text):
        findings.add("rewriting_or_validating_alter")
    if re.search(r"(?is)validate\s+constraint", text) and tables:
        findings.add("synchronous_constraint_validation")
    if re.search(r"(?is)with\s+.+materialized.+(update|delete)", text) and tables:
        findings.add("materialized_full_table_dml")
    if "migration_backfill_tasks" in lower and not re.search(r"checkpoint|scan_upper_bound", lower):
        findings.add("background_task_without_checkpoint")
    return sorted(findings)


def changed_published_without_legacy(path: pathlib.Path) -> bool:
    try:
        old = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"HEAD:{path.relative_to(ROOT)}"],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return False
    if old == path.read_bytes():
        return False
    old_digest = hashlib.sha256(old).hexdigest()
    legacy = (ROOT / "deploy/lib/legacy-migration-checksums.tsv").read_text(encoding="utf-8")
    return f"{path.name}\t{old_digest}" not in legacy


def lint_findings() -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in sql_files():
        codes = sql_findings(path)
        if changed_published_without_legacy(path):
            codes.append("published_checksum_not_registered")
        for code in sorted(set(codes)):
            findings.append({
                "path": str(path.relative_to(ROOT)),
                "sha256": digest(path),
                "code": code,
            })
    for path in shell_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?is)(while\s+:|while\s+true|until\s+false).*?\bsleep\b.*?\bdone\b", text) and not re.search(
            r"deadline|timeout|max_attempt|attempts|seconds\s*[<>]", text, re.I
        ):
            findings.append({
                "path": str(path.relative_to(ROOT)),
                "sha256": digest(path),
                "code": "unbounded_wait_loop",
            })
    return findings


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def command_inventory() -> int:
    steps = inventory()
    for item in steps:
        missing = REQUIRED_FIELDS - set(item)
        if missing:
            raise SystemExit(f"{item.get('path')} missing inventory fields: {sorted(missing)}")
    write_json(INVENTORY, {"schema": "jjdguard-upgrade-inventory/v1", "steps": steps})
    risks = [
        item for item in steps
        if item["risk_level"] in {"MAINTENANCE_REQUIRED", "BLOCKED"}
    ]
    write_json(RISKS, {"schema": "jjdguard-migration-risks/v1", "risks": risks})
    print(f"inventory={len(steps)} high_risk={len(risks)}")
    return 0


def command_baseline() -> int:
    rows = lint_findings()
    entries = [
        {
            **row,
            "reason": "Published historical behavior; tracked in the risk register for staged expand-contract replacement.",
        }
        for row in rows
    ]
    write_json(BASELINE, {"schema": "jjdguard-migration-lint-baseline/v1", "entries": entries})
    print(f"baseline_findings={len(entries)}")
    return 0


def command_lint() -> int:
    current = lint_findings()
    try:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"migration lint baseline unavailable: {error}")
    accepted = {
        (item.get("path"), item.get("sha256"), item.get("code"))
        for item in data.get("entries", [])
        if isinstance(item, dict) and item.get("reason")
    }
    unaccepted = [item for item in current if (item["path"], item["sha256"], item["code"]) not in accepted]
    if unaccepted:
        print(json.dumps({"unaccepted": unaccepted}, indent=2), file=sys.stderr)
        return 1
    print(f"migration_lint=ok accepted_historical={len(current)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("inventory", "baseline", "lint"))
    args = parser.parse_args()
    if args.command == "inventory":
        return command_inventory()
    if args.command == "baseline":
        return command_baseline()
    return command_lint()


if __name__ == "__main__":
    raise SystemExit(main())
