from app.api.check_output import CheckOutputRequest, _run_output_check
from app.detectors.engine import engine

def test_output_scope_exclusion_survives_http_response(monkeypatch):
    from app.detectors.engine import SecurityCheckResult
    monkeypatch.setattr(engine, 'check_output', lambda **kw: SecurityCheckResult(request_id=kw['request_id'],findings=[],action='allow',semantic_status='skipped',semantic_reason='inspection_scope_excluded',semantic_config_revision='test-revision'))
    result=_run_output_check(CheckOutputRequest(request_id='scope',content='hello'))
    assert result.semantic_status=='skipped'
    assert result.semantic_reason=='inspection_scope_excluded'
    assert result.semantic_config_revision=='test-revision'
