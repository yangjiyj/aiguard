"""Offline synthetic file acceptance, run in a separate process from the service."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path


def run(fixtures: Path):
    from app import feature_flags as ff
    from app.detectors.engine import SecurityEngine
    from app.file_readiness import file_detection_readiness
    readiness = file_detection_readiness()
    if not ff.is_enabled(ff.ENV_FILE_CONTENT_DLP) or not readiness["ready"]:
        raise RuntimeError("file DLP selftest requires enabled, ready capabilities")
    results = []
    for audit in (False, True):
        engine = SecurityEngine()
        engine.audit_only = audit
        for name in ("chinese-phone.pdf", "chinese-phone.png", "scanned-chinese-phone.pdf"):
            context = {"attachments": [{"file_name": name, "content_type": "image/png" if name.endswith("png") else "application/pdf", "data_base64": base64.b64encode((fixtures / name).read_bytes()).decode()}]}
            for stage in ("input", "output"):
                result = getattr(engine, "check_" + stage)("synthetic-file-readiness", "普通业务说明", skip_semantic=True, context=context)
                incomplete = any(f.category.startswith("file_content_") or f.type in {"engine_runtime", "semantic_telemetry"} for f in result.raw_findings)
                detected = any(f.category == "phone_cn" and f.content_source == "file_attachment" for f in result.raw_findings)
                # 手机号是未绑定阻断策略的内置检测：附件正文命中与正文一样只告警，
                # 两种模式都应为 audit（不因"来自附件"升级为阻断）。
                passed = detected and not incomplete and result.action == "audit"
                results.append({"fixture": name, "stage": stage, "mode": "audit" if audit else "block", "passed": passed, "coverage_complete": not incomplete})
    return {"passed": all(item["passed"] for item in results), "cases": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=Path("/app/file-fixtures"))
    args = parser.parse_args()
    result = run(args.fixtures)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 1)
