"""Run actual isolated engine + HTTP observer; no classifier/judge mocks and no production connections."""
import argparse
import json
import os
from pathlib import Path
import threading
import time
import uuid


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    output = Path(args.out_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    os.environ.update({"CONTROL_PLANE_URL": "", "JJD_INTERNAL_API_SECRET": token,
        "SECURITY_SCAN_STORE_DIR": "", "SECURITY_SEMANTIC_ENABLED": "true",
        "SECURITY_SEMANTIC_INPUT_ENABLED": "true", "SECURITY_TIER1_ENABLED": "false",
        "SECURITY_LLM_JUDGE_URL": "", "SECURITY_LLM_JUDGE_API_KEY": "",
        "SECURITY_LLM_JUDGE_BACKEND": "disabled", "SECURITY_SEMANTIC_TOTAL_TIMEOUT": "0.2",
        "SECURITY_AUDIT_ONLY": "true", "SECURITY_FILE_CONTENT_DLP_ENABLED": "false"})
    import uvicorn
    from app.main import app
    from app.detectors.engine import engine
    from bench.e2e_bench import digest, run_http, validate_dataset, verify_receipt
    from bench.e2e_observer import observer_server
    source = Path(__file__).parent / "data/e2e_synthetic_smoke.jsonl"
    data = source.read_bytes()
    rows = [json.loads(line) for line in data.decode().splitlines()]
    validate_dataset(rows, [])
    revision = engine.semantic_config_revision
    manifest = {"frozen": True, "split": "blind", "fixture_only": True,
        "dataset_sha256": digest(data), "model_sha256": digest(b"unavailable-no-model"),
        "config_sha256": digest(revision.encode()), "runtime_revision": revision,
        "thresholds": {"tier1_enabled": False}, "training_template_hashes": []}
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(.02)
    if not server.started:
        raise RuntimeError("isolated actual engine failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    run_id = uuid.uuid4().hex
    receipts = output / (run_id + "-observations.jsonl")
    key = uuid.uuid4().hex.encode()
    observer = observer_server(("127.0.0.1", 0), upstream=f"http://127.0.0.1:{port}", receipts=receipts,
                               run_id=run_id, runtime_revision=revision, key=key)
    observer_thread = threading.Thread(target=observer.serve_forever, daemon=True)
    observer_thread.start()
    try:
        report = run_http(rows, mode="engine", base_url=f"http://127.0.0.1:{observer.server_port}", model="none",
                          token=token, timeout=2, concurrency=1, qps=0, manifest=manifest, run_id=run_id)
        signed = [json.loads(line) for line in receipts.read_text().splitlines()]
        if not all(verify_receipt(r, key, run_id, r["request_id"]) for r in signed):
            raise RuntimeError("actual engine observation signature mismatch")
        by_id = {r["id"]: r for r in report["results"]}
        assert by_id["output-canary"]["detected"] is True
        assert by_id["output-canary"]["coverage"] == "complete"
        assert by_id["direct-override"]["coverage"] in {"unknown", "incomplete"}
        assert report["gate"]["passed"] is False
        report["smoke_validation"] = {"actual_engine_http": True, "actual_response_signatures_verified": len(signed),
                                      "semantic_judge_available": False, "accuracy_claim": False}
        (output / "actual-engine-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
        print(json.dumps({"smoke_validation": report["smoke_validation"], "counts": report["counts"], "gate": report["gate"]}))
    finally:
        observer.shutdown(); observer.server_close(); observer_thread.join(timeout=2)
        server.should_exit = True; thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
