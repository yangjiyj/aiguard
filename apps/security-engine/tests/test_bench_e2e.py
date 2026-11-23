import hashlib
import json
import pytest
from bench.e2e_bench import evaluate, summarize, validate_dataset, verify_receipt


def case(label=1, stage="input"):
    return {"id": "synthetic-1", "template_id": "override-a", "label": label, "stage": stage,
            "text": "Synthetic attack", "synthetic": True, "checks": ["semantic" if stage == "input" else "dlp"]}


def test_sent_to_judge_but_judge_benign_is_missed_attack():
    result = evaluate(case(), "engine", 200, {"request_id": "r", "action": "allow", "semantic_status": "completed", "findings": [], "tier1_escalated": True}, request_id="r")
    report = summarize([result])
    assert report["counts"]["detected_attacks"] == 0
    assert report["counts"]["missed_attacks"] == 1
    assert report["detection_recall"] == 0
    assert report["gate"]["passed"] is False


def test_timeout_and_incomplete_remain_in_denominator():
    row = case()
    timed = evaluate(row, "engine", 0, {}, request_id="r", error="TimeoutError")
    incomplete = evaluate(row, "engine", 200, {"request_id": "r", "semantic_status": "incomplete", "action": "allow", "findings": []}, request_id="r")
    report = summarize([timed, incomplete])
    assert report["counts"]["total"] == 2
    assert report["counts"]["missed_attacks"] == 2
    assert report["counts"]["complete"] == 0
    assert report["gate"]["passed"] is False


def test_gateway_200_is_unknown_without_observation():
    result = evaluate(case(), "gateway", 200, {"choices": [{"message": {"content": "ok"}}]}, request_id="r")
    assert result["coverage"] == "unknown"
    assert summarize([result])["unverified_rate"] == 1


@pytest.mark.parametrize("code", ["invalid_api_key", "insufficient_quota", "security_check_failed"])
def test_http_403_is_not_necessarily_security_block(code):
    result = evaluate(case(), "gateway", 403, {"error": {"code": code}}, request_id="r")
    assert result["blocked"] is False
    assert result["error"] == "http_error"


def test_canary_split_across_sse_chunks_still_counts_leak_before_block():
    row = {**case(stage="output"), "canary": "SYNTHETIC_CANARY"}
    data = 'data: {"choices":[{"delta":{"content":"SYNTHETIC_"}}]}\n\ndata: {"choices":[{"delta":{"content":"CANARY"}}]}\n\ndata: {"error":{"code":"security_blocked"}}\n\n'
    result = evaluate(row, "gateway", 200, data, request_id="r")
    assert result["blocked"] is True
    assert result["leaked"] is True
    assert summarize([result])["gate"]["passed"] is False


def test_dataset_rejects_duplicate_and_training_templates():
    row = case()
    with pytest.raises(ValueError, match="template"):
        validate_dataset([row, {**row, "id": "another", "text": "variant"}], [])
    denied = hashlib.sha256(row["template_id"].encode()).hexdigest()
    with pytest.raises(ValueError, match="training"):
        validate_dataset([row], [denied])


def test_gateway_receipt_must_be_bound_and_signed():
    import hmac
    observation = {"run_id": "run1", "request_id": "r", "stage": "input", "coverage": "complete", "detected": True,
                   "engine_request_sha256": "a" * 64, "engine_response_sha256": "b" * 64}
    signature = hmac.new(b"key", json.dumps(observation, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    signed = {**observation, "signature": signature}
    assert verify_receipt(signed, b"key", "run1", "r") is not None
    assert verify_receipt(signed, b"wrong", "run1", "r") is None
    assert verify_receipt(signed, b"key", "other-run", "r") is None



def test_parse_failure_block_is_not_attack_detection():
    result = evaluate(case(), "engine", 200, {"request_id": "r", "action": "block", "semantic_status": "completed",
        "findings": [{"type": "file", "category": "file_content_encrypted", "counts_as_security_finding": True}]}, request_id="r")
    assert result["blocked"] is True
    assert result["detected"] is False
    assert result["coverage"] == "incomplete"


def test_diagnostic_gate_cannot_be_mistaken_for_end_to_end_pass():
    from bench.gate_artifact import extract_gate_artifact
    artifact = extract_gate_artifact({"best": {"low": .3, "high": .7, "cascade_recall_with_gray": 1,
         "benign_false_escalation_rate": 0, "gray_zone_rate": .5}, "gate": {"passed": True}})
    assert artifact["passed"] is True
    assert artifact["scope"] == "tier1_routing_diagnostic"
    assert artifact["end_to_end_passed"] is False



def test_gateway_detected_but_allowed_is_not_enforcement_pass():
    observed = [{"stage": "input", "coverage": "complete", "detected": True,
                 "signals": [{"type": "semantic_attack"}]}]
    attack = evaluate(case(), "gateway", 200, {}, request_id="r", observations=observed)
    benign = evaluate(case(label=0), "gateway", 200, {}, request_id="r", observations=[{**observed[0], "detected": False, "signals": []}])
    report = summarize([attack, benign])
    assert report["counts"]["detected_attacks"] == 1
    assert report["counts"]["enforcement_failures"] == 1
    assert report["gate"]["passed"] is False


def test_absent_output_canary_does_not_prove_prevention_without_probe_observation():
    row = {**case(stage="output"), "canary": "SYNTHETIC_CANARY"}
    observed = [{"stage": "output", "coverage": "complete", "detected": True}]
    result = evaluate(row, "gateway", 200, {"choices": [{"message": {"content": "ordinary"}}]}, request_id="r", observations=observed)
    assert result["leaked"] is False
    assert result["output_probe_verified"] is False
    assert summarize([result])["counts"]["unverified_output_probes"] == 1



def test_parallel_tool_argument_fragments_are_scanned_per_call():
    row = {**case(stage="output"), "canary": "SYNTHETIC_CANARY"}
    parts = [{"choices": [{"index": 0, "delta": {"tool_calls": [
        {"index": 0, "function": {"arguments": "SYNTHETIC_"}},
        {"index": 1, "function": {"arguments": "unrelated"}}]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
        {"index": 0, "function": {"arguments": "CANARY"}}]}}]}]
    payload = "".join("data: " + json.dumps(part) + "\n\n" for part in parts)
    assert evaluate(row, "gateway", 200, payload, request_id="r")["leaked"] is True



def test_inspection_status_and_raw_coverage_findings_cannot_be_hidden():
    base = {"request_id": "r", "semantic_status": "completed", "action": "allow", "findings": []}
    result = evaluate(case(), "engine", 200, {**base, "inspection_status": "incomplete"}, request_id="r")
    assert result["coverage"] == "incomplete"
    result = evaluate(case(), "engine", 200, {**base, "raw_findings": [{"type": "semantic_telemetry"}]}, request_id="r")
    assert result["coverage"] == "incomplete"


def test_unrelated_secret_does_not_inflate_semantic_attack_recall():
    response = {"request_id": "r", "semantic_status": "completed", "action": "audit",
                "findings": [{"type": "secret", "category": "secret_key", "counts_as_security_finding": True}]}
    assert evaluate(case(), "engine", 200, response, request_id="r")["detected"] is False
    dlp = {**case(), "checks": ["dlp"], "expected_categories": ["pii_cn_id_card"]}
    assert evaluate(dlp, "engine", 200, response, request_id="r")["detected"] is False


def test_normal_sse_eof_without_terminal_is_incomplete_even_with_observation():
    data = 'data: {"choices":[{"delta":{"content":"ordinary"}}]}\n\n'
    observed = [{"stage": "input", "coverage": "complete", "detected": False}]
    result = evaluate(case(label=0), "gateway", 200, data, request_id="r", observations=observed)
    assert result["coverage"] == "incomplete"
    assert result["error"] == "stream_incomplete"



def test_malformed_response_keeps_attempt_in_report(monkeypatch):
    import bench.e2e_bench as bench
    monkeypatch.setattr(bench, "http_post", lambda *args: (200, {}, {"request_id": "run-synthetic-1",
        "findings": [{"type": "semantic_attack", "category": None}]}, ""))
    report = bench.run_http([case()], mode="engine", base_url="http://127.0.0.1:1", model="none", token="", timeout=1,
        concurrency=1, qps=0, manifest={"runtime_revision": "frozen"}, run_id="run")
    assert report["counts"]["total"] == 1
    assert report["counts"]["errors"] == 1
    assert report["counts"]["missed_attacks"] == 1
    assert report["artifact_hash_verification"]["model"] == "declared_only"
    assert report["artifact_hash_verification"]["remote_weights_verified"] is False
