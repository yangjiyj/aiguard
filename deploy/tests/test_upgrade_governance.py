import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/upgrade-governance.py"


def test_inventory_contract_and_821_is_expand_only():
    subprocess.run(["python3", str(TOOL), "inventory"], cwd=ROOT, check=True)
    data = json.loads((ROOT / "docs/operations/upgrade-step-inventory.json").read_text())
    steps = {item["step_name"]: item for item in data["steps"]}
    required = {
        "step_name", "version", "mutates_data", "starts_transaction", "lock_level",
        "full_table_scan", "full_table_rewrite", "creates_index", "row_function",
        "network_dependency", "idempotent", "interrupt_resumable", "has_timeout",
        "has_progress", "blocks_service_start", "complexity", "disk_wal_risk",
        "risk_level", "tests",
    }
    assert required <= set(steps["821_serialize_customer_content_projection.sql"])
    assert not steps["821_serialize_customer_content_projection.sql"]["row_function"]
    assert not steps["821_serialize_customer_content_projection.sql"]["full_table_scan"]
    assert steps["834_customer_content_projection_backfill.sql"]["interrupt_resumable"]


def test_lint_baseline_is_current():
    subprocess.run(["python3", str(TOOL), "lint"], cwd=ROOT, check=True)


def test_ddl_cascades_and_trigger_events_are_not_unbounded_dml(tmp_path):
    import importlib.util
    spec=importlib.util.spec_from_file_location("upgrade_governance_test",TOOL)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    ddl=tmp_path/"ddl.sql"
    ddl.write_text("CREATE TABLE x(id int REFERENCES y(id) ON DELETE CASCADE); CREATE TRIGGER t BEFORE UPDATE OF id ON x EXECUTE FUNCTION f();")
    assert "unbounded_update_delete" not in module.sql_findings(ddl)
    dml=tmp_path/"dml.sql";dml.write_text("UPDATE request_logs SET request_status='unknown';")
    assert "unbounded_update_delete" in module.sql_findings(dml)


def test_declared_migration_tests_are_registered():
    """迁移文件里用 -- governance-test: 声明的真库用例要登记进升级步骤清单（1010 的两条证据身份用例）。"""
    subprocess.run(["python3", str(TOOL), "inventory"], cwd=ROOT, check=True)
    data = json.loads((ROOT / "docs/operations/upgrade-step-inventory.json").read_text())
    steps = {item["step_name"]: item for item in data["steps"]}
    tests = steps["1010_alert_evidence_identity_raw.sql"]["tests"]
    assert "deploy/tests/test_migration_runner.sh" in tests
    assert "apps/gateway-core/internal/handler/alert_raw_evidence_db_test.go::TestRawEvidenceSummaryKeepsAlertReadMetadataOnPostgres" in tests
    assert "apps/control-plane/internal/repository/alert_evidence_identity_raw_db_test.go::TestRawEvidenceEventsKeepCaseAndEvidenceNoveltyOnPostgres" in tests
    for item in data["steps"]:
        for test in item["tests"]:
            path = test.split("::", 1)[0]
            assert (ROOT / path).exists(), f"{item['step_name']} declares missing test {test}"


def test_trigger_ddl_reports_share_row_exclusive(tmp_path):
    # CREATE/DROP TRIGGER 在表上取 SHARE ROW EXCLUSIVE：会挡住写入，不是“只改元数据”。
    import importlib.util
    spec = importlib.util.spec_from_file_location("upgrade_governance_lock_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = module.ROOT
    trigger = root / "deploy/migrations/__lock_probe_trigger.sql"
    function_only = root / "deploy/migrations/__lock_probe_function.sql"
    try:
        trigger.write_text("DROP TRIGGER IF EXISTS t ON x;\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH STATEMENT EXECUTE FUNCTION f();\n")
        function_only.write_text("CREATE OR REPLACE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n  -- CREATE TRIGGER inside a body is not DDL\n  RETURN NULL;\nEND;\n$$;\n")
        assert module.sql_inventory(trigger)["lock_level"] == "SHARE ROW EXCLUSIVE"
        assert module.sql_inventory(function_only)["lock_level"] == "none/metadata"
    finally:
        trigger.unlink(missing_ok=True)
        function_only.unlink(missing_ok=True)


def test_trigger_ddl_lists_its_tables_and_requires_a_write_pause(tmp_path):
    # 建删触发器的迁移：清单里要列出触发器所在的表，并注明需要停写入执行（SHARE ROW EXCLUSIVE 会挡住写入）。
    import importlib.util
    spec = importlib.util.spec_from_file_location("upgrade_governance_tables_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    probe = module.ROOT / "deploy/migrations/__trigger_tables_probe.sql"
    try:
        probe.write_text("BEGIN;\nDROP TRIGGER IF EXISTS t ON internal_keys;\nCREATE TRIGGER t AFTER UPDATE ON audit_dispositions FOR EACH ROW EXECUTE FUNCTION f();\nCOMMIT;\n")
        item = module.sql_inventory(probe)
        assert {"internal_keys", "audit_dispositions"} <= set(item["tables"])
        assert item["requires_write_pause"] is True
        assert "停写入" in item["operator_note"]
    finally:
        probe.unlink(missing_ok=True)
