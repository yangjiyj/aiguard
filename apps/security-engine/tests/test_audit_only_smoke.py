from app.detectors.engine import SecurityCheckResult, SecurityEngine, SecurityFinding


def test_audit_only_smoke_passes_and_forwards_both_chains(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")

    from app.audit_only_smoke import run_smoke

    report = run_smoke(SecurityEngine())

    assert report.ok is True
    assert {case.chain for case in report.cases} == {"forward", "reverse"}
    assert all(case.action == "audit" for case in report.cases)
    assert all(case.forwarded for case in report.cases)


def test_audit_only_smoke_fails_when_reverse_chain_blocks(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    engine = SecurityEngine()

    def _blocking_check_output(request_id, content, context=None):
        return SecurityCheckResult(
            request_id=request_id,
            findings=[
                SecurityFinding(
                    type="pii",
                    category="id_card_cn",
                    severity="critical",
                    matched_text_preview="12****7X",
                    rule_id="regex_id_card_cn",
                    confidence=0.95,
                )
            ],
            action="block",
            masked_content=None,
            original_hash="smoke-test",
        )

    engine.check_output = _blocking_check_output

    from app.audit_only_smoke import run_smoke

    report = run_smoke(engine)

    assert report.ok is False
    reverse = next(case for case in report.cases if case.chain == "reverse")
    assert reverse.action == "block"
    assert reverse.forwarded is False
    assert "expected action=audit" in reverse.error


def test_audit_only_smoke_main_returns_nonzero_on_failure(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")

    from app import audit_only_smoke

    def _failed_report(engine=None):
        return audit_only_smoke.SmokeReport(
            ok=False,
            cases=[
                audit_only_smoke.SmokeCaseResult(
                    chain="forward",
                    action="block",
                    findings_count=1,
                    forwarded=False,
                    upstream_status=None,
                    error="expected action=audit, got block",
                )
            ],
        )

    monkeypatch.setattr(audit_only_smoke, "run_smoke", _failed_report)

    assert audit_only_smoke.main([]) == 1
