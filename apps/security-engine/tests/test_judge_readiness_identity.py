import concurrent.futures
import hashlib
import io
import json
import threading
import pytest
from app.detectors import llm_judge as judge
from app import semantic_config_loader as loader

URL = 'http://llm-judge:8080/v1/chat/completions'
OPTIONS = dict(url=URL, model='bundled-judge', api_key='fixture-a', timeout=24,
               judge_backend='bundled', allow_private_egress=False)
CONTENT = 'JJDGuard semantic runtime health check. Treat this sentence as benign.'
VALID = json.dumps(dict(assessment='benign', verdict='benign', category='none',
                       confidence=0.99, reason='healthy'))

@pytest.fixture(autouse=True)
def isolated_state(monkeypatch):
    judge._reset_breakers()
    monkeypatch.setattr(loader, '_managed_judge_probe_state', {}, raising=False)
    yield
    judge._reset_breakers()

def config(**changes):
    value = dict(revision='a'*32, judge_url=URL, judge_model='bundled-judge',
                 judge_api_key='fixture-a', judge_timeout=24,
                 judge_backend='bundled', judge_allow_private_egress=False,
                 semantic_total_timeout=25)
    value.update(changes)
    return value

def scoped(options=None):
    return judge.semantic_judge_health_identity(**(options or OPTIONS))

def health(options=None):
    return judge.get_semantic_judge_health(URL, identity=scoped(options))

def fake_transport(monkeypatch, responses):
    items = iter(responses)
    monkeypatch.setattr(judge, '_validated_managed_target',
        lambda *a, **k: judge.PinnedJudgeTarget(URL, '172.30.0.2'))
    monkeypatch.setattr(judge, '_slot_gate_for', lambda *a, **k: None)
    def opened(*a, **k):
        value = next(items)
        if isinstance(value, BaseException):
            raise value
        return io.BytesIO(json.dumps({'choices': [{'finish_reason': 'stop',
            'message': {'content': value}}]}).encode())
    monkeypatch.setattr(judge, '_open_pinned', opened)

def test_expired_parsed_success_is_not_operational(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(judge.time, 'monotonic', lambda: now[0])
    judge._record_semantic_judge_attempt(URL, True)
    assert judge.get_semantic_judge_health(URL)['operational'] is True
    now[0] += 301
    assert judge.get_semantic_judge_health(URL)['operational'] is False

def test_configuration_identity_is_secret_opaque_and_complete(monkeypatch):
    original = scoped()
    assert len(original) == 64 and 'fixture-a' not in original
    for change in [dict(model='another'), dict(api_key='fixture-b'), dict(judge_backend='external'),
                   dict(allow_private_egress=True), dict(timeout=23), dict(url=URL+'?v=2')]:
        assert scoped(dict(OPTIONS, **change)) != original
    monkeypatch.setenv('SECURITY_SEMANTIC_JUDGE_JSON_SCHEMA', 'false')
    assert scoped() != original

def test_success_and_parse_failure_are_scoped_to_configuration(monkeypatch):
    monkeypatch.setattr(judge, '_post_chat', lambda *a, **k: VALID)
    assert judge.judge_semantic(CONTENT, **OPTIONS) is not None
    other = dict(OPTIONS, model='different-model')
    assert health()['operational'] is True
    assert health(other)['operational'] is False
    assert not judge.has_recent_semantic_judge_success(URL, identity=scoped(other))
    monkeypatch.setattr(judge, '_post_chat', lambda *a, **k: 'not-json')
    assert judge.judge_semantic(CONTENT, **other) is None
    assert not judge.has_recent_semantic_judge_success(URL, identity=scoped(other))
    assert health()['operational'] is True
    assert 'fixture-a' not in json.dumps(health())

def test_breaker_and_window_do_not_poison_a_different_key(monkeypatch):
    monkeypatch.setenv('SECURITY_SEMANTIC_BREAKER_THRESHOLD', '2')
    fake_transport(monkeypatch, [TimeoutError(), TimeoutError(), VALID])
    assert judge.judge_semantic(CONTENT, **OPTIONS) is None
    assert judge.judge_semantic(CONTENT, **OPTIONS) is None
    assert health()['breaker_open'] is True
    other = dict(OPTIONS, api_key='fixture-b')
    assert judge.judge_semantic(CONTENT, **other) is not None
    assert health(other)['operational'] is True
    assert health(other)['window_attempts'] == 1
    assert health()['breaker_open'] is True
    assert health()['window_timeouts'] == 2

def test_window_veto_and_parse_freshness_both_remain(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(judge.time, 'monotonic', lambda: now[0])
    fake_transport(monkeypatch, [TimeoutError(), VALID, VALID, VALID, VALID, VALID])
    for _ in range(5):
        judge.judge_semantic(CONTENT, **OPTIONS)
    assert health()['window_attempts'] == 5
    assert health()['window_successes'] == 4
    assert health()['operational'] is False
    now[0] += 301
    assert health()['operational'] is False
    assert judge.judge_semantic(CONTENT, **OPTIONS) is not None
    assert health()['window_attempts'] == 1
    assert health()['operational'] is True

def prepare_loader(monkeypatch, *, recent, operational=True, opinion=True):
    calls = []
    guard = threading.Lock()
    def call(content, **kwargs):
        with guard:
            calls.append((content, kwargs))
        return judge.SemanticOpinion('benign', 'none', .99, 'healthy') if opinion else None
    monkeypatch.setattr(judge, 'judge_semantic', call)
    monkeypatch.setattr(judge, 'get_semantic_judge_health',
        lambda url, **kwargs: {'operational': operational, 'window_attempts': 2 if operational else 6,
                             'window_successes': 2 if operational else 4, 'window_timeouts': 0 if operational else 2})
    monkeypatch.setattr(judge, 'has_recent_semantic_judge_success',
        lambda *a, **k: recent[0], raising=False)
    return calls

def test_first_probe_requires_real_concurrent_pair_with_unchanged_budget(monkeypatch):
    calls = prepare_loader(monkeypatch, recent=[False])
    original = judge.judge_semantic
    barrier = threading.Barrier(2)
    def simultaneous(*a, **k):
        barrier.wait(timeout=2)
        return original(*a, **k)
    monkeypatch.setattr(judge, 'judge_semantic', simultaneous)
    value = loader._probe_managed_judge(config())
    assert value['operational'] is True
    assert len(calls) == 2
    assert all(text == CONTENT and options == OPTIONS for text, options in calls)

def test_recent_pair_skips_extra_inference_but_config_change_forces_new_pair(monkeypatch):
    recent = [True]
    calls = prepare_loader(monkeypatch, recent=recent)
    loader._probe_managed_judge(config())
    loader._probe_managed_judge(config())
    assert len(calls) == 2
    loader._probe_managed_judge(config(judge_api_key='fixture-b'))
    assert len(calls) == 4
    loader._probe_managed_judge(config(judge_api_key='fixture-b', semantic_total_timeout=24))
    assert len(calls) == 6

def test_expired_evidence_forces_new_real_pair(monkeypatch):
    recent = [True]
    calls = prepare_loader(monkeypatch, recent=recent)
    loader._probe_managed_judge(config())
    recent[0] = False
    loader._probe_managed_judge(config())
    assert len(calls) == 4

def test_capacity_skip_does_not_establish_pair_readiness(monkeypatch):
    calls = prepare_loader(monkeypatch, recent=[True], opinion=False)
    assert loader._probe_managed_judge(config())['operational'] is False
    assert loader._probe_managed_judge(config())['operational'] is False
    assert len(calls) == 4

def test_cached_pair_keeps_low_success_window_degraded(monkeypatch):
    calls = prepare_loader(monkeypatch, recent=[True], operational=False)
    first = loader._probe_managed_judge(config())
    second = loader._probe_managed_judge(config())
    assert not first['operational'] and not second['operational']
    assert second['window_attempts'] == 6 and second['window_timeouts'] == 2
    assert len(calls) == 2

def test_original_request_payload_is_unchanged(monkeypatch):
    monkeypatch.setenv('SECURITY_SEMANTIC_JUDGE_JSON_SCHEMA', 'true')
    captured = []
    def transport(url, body, api_key, timeout, **kwargs):
        captured.append((body, timeout))
        return VALID
    monkeypatch.setattr(judge, '_post_chat', transport)
    judge.judge_semantic(CONTENT, **OPTIONS)
    assert captured[0][1] == 24
    assert hashlib.sha256(captured[0][0]).hexdigest() == 'b8485f7c4bfac679120462ee7a04b412ab716d7468b923069f5a120317085f4d'


def test_late_parsed_success_cannot_hide_open_breaker(monkeypatch):
    monkeypatch.setenv('SECURITY_SEMANTIC_BREAKER_THRESHOLD', '2')
    fake_transport(monkeypatch, [TimeoutError(), TimeoutError()])
    for _ in range(2):
        judge.judge_semantic(CONTENT, **OPTIONS)
    assert health()['breaker_open'] is True
    # A response already in parsing can finish after another lease opened the breaker.
    monkeypatch.setattr(judge, '_post_chat', lambda *a, **k: VALID)
    judge.judge_semantic(CONTENT, **OPTIONS)
    assert health()['operational'] is False
    assert not judge.has_recent_semantic_judge_success(URL, identity=scoped())


def test_shortened_caller_budget_keeps_normal_configuration_identity():
    expected = scoped()
    with judge.judge_health_budget(24):
        assert scoped(dict(OPTIONS, timeout=23.12345)) == expected
        assert scoped(dict(OPTIONS, timeout=17.98765)) == expected


def test_initial_readiness_small_sample_with_failures_waits_to_age_out(monkeypatch):
    calls = prepare_loader(monkeypatch, recent=[True])
    window = {'operational': True, 'window_attempts': 4, 'window_successes': 2, 'window_timeouts': 2}
    monkeypatch.setattr(judge, 'get_semantic_judge_health', lambda *a, **k: dict(window))
    assert loader._probe_managed_judge(config())['operational'] is False
    assert loader._probe_managed_judge(config())['operational'] is False
    assert len(calls) == 2
    window.update(window_attempts=2, window_successes=2, window_timeouts=0)
    assert loader._probe_managed_judge(config())['operational'] is True
    assert len(calls) == 2
    window.update(window_attempts=20, window_successes=19, window_timeouts=1)
    assert loader._probe_managed_judge(config())['operational'] is True


@pytest.mark.parametrize('backend', ['custom', 'provider'])
def test_external_backend_keeps_single_probe_capacity(monkeypatch, backend):
    calls = prepare_loader(monkeypatch, recent=[True])
    value = loader._probe_managed_judge(config(judge_backend=backend, judge_url='https://judge.example/v1/chat/completions'))
    assert value['operational'] is True
    assert len(calls) == 1
    assert calls[0][1]['timeout'] == 24


def _ready_with(monkeypatch, **window):
    prepare_loader(monkeypatch, recent=[True])
    state = {'operational': True, 'window_attempts': 30, 'window_successes': 29, 'window_timeouts': 1}
    state.update(window)
    monkeypatch.setattr(judge, 'get_semantic_judge_health', lambda *a, **k: dict(state))
    return state

def test_field_scenario_29_of_30_is_ready_after_signature_change(monkeypatch):
    _ready_with(monkeypatch)
    assert loader._probe_managed_judge(config())['operational'] is True
    assert loader._managed_judge_probe_state['ready_once'] is True

def test_small_sample_with_failure_is_not_ready(monkeypatch):
    _ready_with(monkeypatch, window_attempts=4, window_successes=3, window_timeouts=1)
    assert loader._probe_managed_judge(config())['operational'] is False
    assert loader._managed_judge_probe_state.get('ready_once') is not True

def test_low_success_rate_is_not_ready(monkeypatch):
    _ready_with(monkeypatch, operational=False, window_attempts=30, window_successes=20, window_timeouts=10)
    assert loader._probe_managed_judge(config())['operational'] is False
    assert loader._managed_judge_probe_state.get('ready_once') is not True

def test_pair_not_ready_is_not_ready(monkeypatch):
    prepare_loader(monkeypatch, recent=[True], opinion=False)
    monkeypatch.setattr(judge, 'get_semantic_judge_health', lambda *a, **k: {
        'operational': True, 'window_attempts': 30, 'window_successes': 30, 'window_timeouts': 0})
    assert loader._probe_managed_judge(config())['operational'] is False

def test_ready_then_floor_breach_is_unavailable(monkeypatch):
    state = _ready_with(monkeypatch)
    assert loader._probe_managed_judge(config())['operational'] is True
    state.update(operational=False, window_successes=20, window_timeouts=10)
    assert loader._probe_managed_judge(config())['operational'] is False

def test_new_identity_window_not_polluted_by_old_config_failures():
    old = judge.semantic_judge_health_identity(**OPTIONS)
    new = judge.semantic_judge_health_identity(**dict(OPTIONS, api_key='fixture-b'))
    with judge._semantic_judge_scope(old, old):
        for _ in range(10):
            judge._record_semantic_judge_window(URL, success=False, timed_out=True, latency_ms=1)
    assert judge.get_semantic_judge_health(URL, identity=old)['window_attempts'] == 10
    assert judge.get_semantic_judge_health(URL, identity=new)['window_attempts'] == 0
