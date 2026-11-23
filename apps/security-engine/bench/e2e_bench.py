"""Frozen full-chain HTTP evaluation; never infer final recall from Tier-1 routing."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from bench.run_bench import percentile

SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def validate_dataset(rows, training_template_hashes):
    ids, templates, texts = set(), set(), set()
    for row in rows:
        canonical(row)
        if row.get("synthetic") is not True:
            raise ValueError("only reviewed synthetic fixtures are accepted")
        if not SAFE_ID.fullmatch(str(row.get("id", ""))) or row["id"] in ids:
            raise ValueError("case id invalid or duplicate")
        template = row.get("template_id", "")
        if not SAFE_ID.fullmatch(template) or template in templates:
            raise ValueError("template invalid or duplicate; deduplicate before blind test")
        if digest(template.encode()) in training_template_hashes:
            raise ValueError("blind template overlaps training or threshold-tuning data")
        if row.get("label") not in (0, 1) or row.get("stage") not in ("input", "output"):
            raise ValueError("label/stage invalid")
        if not isinstance(row.get("text"), str) or len(row["text"]) > 1_000_000:
            raise ValueError("text invalid or beyond fixture budget")
        text_hash = digest(" ".join(row["text"].split()).casefold().encode())
        if text_hash in texts:
            raise ValueError("duplicate normalized text")
        if not set(row.get("checks", [])) or not set(row["checks"]) <= {"semantic", "dlp"}:
            raise ValueError("explicit semantic/dlp checks required")
        if row["stage"] == "output" and row["label"] == 1 and not row.get("canary"):
            raise ValueError("output attack fixture requires a synthetic leak canary")
        ids.add(row["id"]); templates.add(template); texts.add(text_hash)


def validate_manifest(manifest, dataset_bytes):
    canonical(manifest)  # reject NaN/Infinity before sending requests
    if manifest.get("split") != "blind" or manifest.get("frozen") is not True:
        raise ValueError("freeze a blind manifest before sending any test request")
    for field in ("dataset_sha256", "model_sha256", "config_sha256"):
        if not SHA256.fullmatch(str(manifest.get(field, ""))):
            raise ValueError("manifest requires " + field)
    if manifest["dataset_sha256"] != digest(dataset_bytes):
        raise ValueError("dataset hash changed after freeze")
    for field, default in (("recall_min", 1.0), ("false_block_max", 0.0)):
        if not 0 <= float(manifest.get(field, default)) <= 1:
            raise ValueError("invalid acceptance threshold")
    if not isinstance(manifest.get("thresholds"), dict) or not manifest.get("runtime_revision"):
        raise ValueError("frozen thresholds and expected runtime_revision required")


def _response_parts(payload):
    if isinstance(payload, dict):
        return [payload]
    if not isinstance(payload, str):
        return []
    try:
        parsed = json.loads(payload)
        return [parsed] if isinstance(parsed, dict) else []
    except ValueError:
        parts = []
        for line in payload.splitlines():
            if line.startswith("data:"):
                try:
                    item = json.loads(line[5:].strip())
                    if isinstance(item, dict):
                        parts.append(item)
                except ValueError:
                    pass
        return parts


def _strings(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_strings(item) for item in value)
    if isinstance(value, dict):
        return "".join(_strings(item) for item in value.values())
    return ""


def _generated_text(parts):
    # Keep parallel choices/tool calls separate when rebuilding incrementally emitted arguments.
    channels = {}
    other = []
    for part in parts:
        for choice in part.get("choices", []):
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            payload = choice.get("delta", choice.get("message", {"content": choice.get("text", "")}))
            if not isinstance(payload, dict):
                channels.setdefault((index, "content"), []).append(_strings(payload))
                continue
            channels.setdefault((index, "content"), []).append(_strings(payload.get("content", "")))
            for call in payload.get("tool_calls", []):
                if isinstance(call, dict):
                    channels.setdefault((index, "tool", call.get("index", 0)), []).append(
                        _strings(call.get("function", {}).get("arguments", "")))
            if payload.get("function_call"):
                channels.setdefault((index, "legacy_function"), []).append(
                    _strings(payload["function_call"].get("arguments", "")))
        if not part.get("choices"):
            other.append(_strings(part))
    return "\n".join("".join(chunks) for chunks in channels.values()) + "\n" + "".join(other)


def verify_receipt(receipt, key, run_id, request_id):
    if not key or not isinstance(receipt, dict):
        return None
    data = {k: v for k, v in receipt.items() if k != "signature"}
    signature = hmac.new(key, canonical(data), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, str(receipt.get("signature", ""))):
        return None
    if data.get("run_id") != run_id or data.get("request_id") != request_id:
        return None
    if any(not SHA256.fullmatch(str(data.get(k, ""))) for k in ("engine_request_sha256", "engine_response_sha256")):
        return None
    return data


def finding_matches_scope(finding, row):
    if not isinstance(finding, dict) or finding.get("counts_as_security_finding", True) is not True:
        return False
    if finding.get("triage", {}).get("disposition") == "observation":
        return False
    category = finding.get("category", "")
    if category.startswith("file_content_"):
        return False
    expected = row.get("expected_categories", [])
    if expected and category not in expected:
        return False
    kind = finding.get("type")
    return (("semantic" in row["checks"] and kind == "semantic_attack")
            or ("dlp" in row["checks"] and kind in {"pii", "secret", "code_config", "sensitive_data", "data_leak"})
            or ("dlp" in row["checks"] and kind == "custom" and bool(expected)))


def evaluate(row, mode, status, payload, *, request_id, error="", observations=(), latency_ms=0.0,
             expected_revision=""):
    parts = _response_parts(payload)
    obj = parts[0] if parts else {}
    blocked = False
    detected = False
    coverage = "unknown"
    if mode == "engine":
        if status == 200 and obj.get("request_id") == request_id:
            findings = obj.get("findings", [])
            detected = any(finding_matches_scope(f, row) for f in findings)
            blocked = obj.get("action") in {"block", "reply"}
            incomplete = any(f.get("type") in {"engine_runtime", "semantic_telemetry"}
                             or f.get("triage", {}).get("semantic_status") == "incomplete"
                             or f.get("triage", {}).get("disposition_reason") == "coverage_gap"
                             or f.get("category", "").startswith("file_content_")
                             for f in [*findings, *obj.get("raw_findings", [])] if isinstance(f, dict))
            if obj.get("inspection_status") not in (None, "completed"):
                incomplete = True
            if "semantic" in row["checks"]:
                coverage = "complete" if obj.get("semantic_status") == "completed" else "incomplete"
                if expected_revision and obj.get("semantic_config_revision") != expected_revision:
                    coverage = "unknown"
            else:
                # A direct successful deterministic endpoint response is execution evidence.
                coverage = "complete"
            if incomplete:
                coverage = "incomplete"
        elif status:
            error = "http_error"
    else:
        blocked = any(part.get("error", {}).get("code") == "security_blocked" for part in parts
                      if isinstance(part.get("error", {}), dict))
        if status >= 400 and not blocked:
            error = "http_error"
        matching = [o for o in observations if o.get("stage") == row["stage"]]
        if matching:
            coverage = "complete" if all(o.get("coverage") == "complete" for o in matching) else "incomplete"
            if expected_revision and any(o.get("runtime_revision") != expected_revision for o in matching):
                coverage = "unknown"
            detected = any(finding_matches_scope(signal, row)
                           for o in matching for signal in o.get("signals", []))
        is_sse = isinstance(payload, str) and any(line.startswith(("data:", "event:")) for line in payload.splitlines())
        terminal = (is_sse and any(line.partition(":")[2].strip() == "[DONE]"
                    for line in payload.splitlines() if line.startswith("data:")))
        terminal = terminal or any(part.get("type") in {"response.completed", "message_stop"} for part in parts)
        if status == 200 and is_sse and not terminal and not blocked:
            error = error or "stream_incomplete"
        elif status == 200 and not parts:
            error = error or "protocol_incomplete"
        if not blocked and any(part.get("error") for part in parts):
            error = error or "upstream_stream_error"
    if error:
        coverage = "incomplete"
    canary = row.get("canary", "")
    leaked = bool(mode == "gateway" and canary and (canary in _generated_text(parts)
                  or (isinstance(payload, str) and canary in payload)))
    output_probe_verified = not (mode == "gateway" and row["stage"] == "output" and row["label"] == 1)
    if not output_probe_verified:
        output_probe_verified = any(digest(canary.encode()) in o.get("canary_hashes_seen", [])
                                    for o in observations if o.get("stage") == "output")
    enforcement_failure = mode == "gateway" and row["stage"] == "input" and row["label"] == 1 and not blocked
    # Never persist payloads, free-form errors, evidence previews, or credentials.
    return {"id": row["id"], "label": row["label"], "stage": row["stage"], "http_status": status,
            "coverage": coverage, "detected": detected, "blocked": blocked, "leaked": leaked,
            "output_probe_verified": output_probe_verified, "enforcement_failure": enforcement_failure,
            "error": error if error in {"http_error", "TimeoutError", "URLError", "OSError", "response_budget", "stream_incomplete", "protocol_incomplete", "upstream_stream_error", "malformed_response"} else ("transport_error" if error else ""),
            "latency_ms": round(latency_ms, 3)}


def summarize(results, recall_min=1.0, false_block_max=0.0):
    total = len(results)
    attacks = [r for r in results if r["label"] == 1]
    benign = [r for r in results if r["label"] == 0]
    detected = sum(r["detected"] and r["coverage"] == "complete" and not r["error"] for r in attacks)
    blocked = sum(r["blocked"] and not r["error"] for r in attacks)
    false_blocks = sum(r["blocked"] for r in benign)
    counts = {"total": total, "attack": len(attacks), "benign": len(benign),
              "complete": sum(r["coverage"] == "complete" for r in results),
              "incomplete": sum(r["coverage"] == "incomplete" for r in results),
              "unknown": sum(r["coverage"] == "unknown" for r in results),
              "errors": sum(bool(r["error"]) for r in results), "detected_attacks": detected,
              "missed_attacks": len(attacks) - detected, "blocked_attacks": blocked,
              "false_blocks": false_blocks, "leaked_outputs": sum(r["leaked"] for r in results),
              "false_detections": sum(r["detected"] and r["coverage"] == "complete" for r in benign),
              "enforcement_failures": sum(r["enforcement_failure"] for r in results),
              "unverified_output_probes": sum(not r["output_probe_verified"] for r in results)}
    recall = detected / len(attacks) if attacks else 0.0
    false_block_rate = false_blocks / len(benign) if benign else 0.0
    passed = (bool(attacks) and bool(benign) and recall >= recall_min and false_block_rate <= false_block_max
              and not (counts["incomplete"] or counts["unknown"] or counts["errors"] or counts["leaked_outputs"]
                      or counts["enforcement_failures"] or counts["unverified_output_probes"]))
    latencies = [r["latency_ms"] for r in results]
    return {"scope": "full_chain_http", "counts": counts, "detection_recall": recall,
            "attack_block_rate": blocked / len(attacks) if attacks else 0.0,
            "false_block_rate": false_block_rate,
            "false_detection_rate": counts["false_detections"] / len(benign) if benign else 0.0,
            "unverified_rate": counts["unknown"] / total if total else 1.0,
            "completion_rate": counts["complete"] / total if total else 0.0,
            "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95), "p99": percentile(latencies, 99)},
            "gate": {"passed": passed, "requires_complete_evidence": True}, "results": results}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_post(url, payload, headers, timeout):
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, data=canonical(payload), headers={"Content-Type": "application/json", **headers}, method="POST")
    body = bytearray()
    response_status, response_headers = 0, {}
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            response_status, response_headers = response.code, dict(response.headers)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                # read1 returns currently available bytes; avoid waiting for a full chunk in SSE.
                if getattr(response, "fp", None) and getattr(response.fp, "raw", None):
                    sock = getattr(response.fp.raw, "_sock", None)
                    if sock is not None:
                        sock.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    return response.code, dict(response.headers), body.decode("utf-8", "replace"), "response_budget"
            return response.code, dict(response.headers), body.decode("utf-8", "replace"), ""
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return response_status, response_headers, body.decode("utf-8", "replace"), type(exc).__name__


def make_request(row, mode, request_id, model):
    if mode == "engine":
        payload = {"request_id": request_id, "content": row["text"], "context": {"tenant_id": "bench-synthetic"}}
        if row["stage"] == "input":
            payload["content_source"] = row.get("content_source", "user")
        return "/check-" + row["stage"] + "/", payload
    messages = row.get("gateway_messages") or [{"role": "user", "content": row.get("gateway_prompt", row["text"])}]
    return "/v1/chat/completions", {"model": model, "messages": messages, "stream": row.get("stream", True)}


def run_http(rows, *, mode, base_url, model, token, timeout, concurrency, qps, manifest,
             run_id, receipt_path=None, receipt_key=b"", artifact_verification=None):
    if concurrency < 1 or not math.isfinite(qps) or qps < 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("positive concurrency/timeout and nonnegative qps required")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URL must be explicit HTTP(S), without credentials/query")
    headers = {"X-JJDGuard-Internal-Token": token} if mode == "engine" else {"Authorization": "Bearer " + token}
    started = time.monotonic()
    def one(row):
        request_id = run_id + "-" + row["id"]
        path, payload = make_request(row, mode, request_id, model)
        before = time.monotonic()
        status, response_headers, body, error = http_post(base_url.rstrip("/") + path, payload, headers, timeout)
        observed_id = next((v for k, v in response_headers.items() if k.lower() == "x-request-id"), "")
        observations = []
        if mode == "gateway" and receipt_path and observed_id and Path(receipt_path).exists():
            for line in Path(receipt_path).read_text().splitlines():
                try:
                    receipt = verify_receipt(json.loads(line), receipt_key, run_id, observed_id)
                    if receipt is not None:
                        observations.append(receipt)
                except ValueError:
                    continue
        return evaluate(row, mode, status, body, request_id=request_id, error=error,
                        observations=observations, latency_ms=(time.monotonic()-before)*1000,
                        expected_revision=manifest["runtime_revision"])
    def safely_one(row):
        try:
            return one(row)
        except Exception:
            # Malformed upstream/observation payloads count as failed attempts; never drop a case.
            return evaluate(row, mode, 0, {}, request_id=run_id + "-" + row["id"], error="malformed_response")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        pending = set()
        for index, row in enumerate(rows):
            if len(pending) >= concurrency:
                done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
                results.extend(f.result() for f in done)
            if qps:
                delay = started + index / qps - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            pending.add(executor.submit(safely_one, row))
        results.extend(f.result() for f in concurrent.futures.as_completed(pending))
    report = summarize(results, manifest.get("recall_min", 1.0), manifest.get("false_block_max", 0.0))
    report.update({"run_id": run_id, "mode": mode, "frozen_manifest": manifest,
                   "offered_qps": qps, "concurrency": concurrency, "duration_seconds": time.monotonic()-started,
                   "artifact_hash_verification": {"model": "declared_only", "config": "declared_only",
                      **(artifact_verification or {}), "remote_weights_verified": False}})
    if manifest.get("fixture_only"):
        report["gate"]["passed"] = False
        report["gate"]["reason"] = "synthetic smoke fixture is not independent production accuracy evidence"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("engine", "gateway"), required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--model", default="bench-model")
    parser.add_argument("--model-artifact", help="Optional local weight artifact to verify against frozen hash")
    parser.add_argument("--config-artifact", help="Optional sanitized config artifact to verify against frozen hash")
    parser.add_argument("--token-env", default="JJD_BENCH_TOKEN")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--qps", type=float, default=0)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--receipts")
    parser.add_argument("--receipt-key-env", default="JJD_BENCH_RECEIPT_KEY")
    parser.add_argument("--json-out", required=True)
    args = parser.parse_args(argv)
    data = Path(args.dataset).read_bytes()
    manifest = json.loads(Path(args.manifest).read_text())
    validate_manifest(manifest, data)
    artifact_verification = {}
    for path, field in ((args.model_artifact, "model_sha256"), (args.config_artifact, "config_sha256")):
        if path:
            with Path(path).open("rb") as source:
                actual = hashlib.file_digest(source, "sha256").hexdigest()
            if actual != manifest[field]:
                parser.error("frozen artifact hash mismatch: " + field)
            artifact_verification[field.removesuffix("_sha256")] = "local_verified"
    rows = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
    validate_dataset(rows, manifest.get("training_template_hashes", []))
    run_id = args.run_id or uuid.uuid4().hex
    if not SAFE_ID.fullmatch(run_id):
        parser.error("run-id must be a synthetic identifier")
    report = run_http(rows, mode=args.mode, base_url=args.base_url, model=args.model,
                      token=os.getenv(args.token_env, ""), timeout=args.timeout, concurrency=args.concurrency,
                      qps=args.qps, manifest=manifest, run_id=run_id, receipt_path=args.receipts,
                      receipt_key=os.getenv(args.receipt_key_env, "").encode(), artifact_verification=artifact_verification)
    Path(args.json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    print(json.dumps({"scope": report["scope"], "counts": report["counts"], "gate": report["gate"]}))
    return 0 if report["gate"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
