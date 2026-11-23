"""Bind a deployment candidate to its exact model, preprocessing and evidence."""
import hashlib
import json
from pathlib import Path

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
    return h.hexdigest()

def validate_candidate(root,manifest):
    root=Path(root).resolve()
    if manifest.get("schema")!="jjdguard.judge_candidate/v1":
        raise ValueError("unsupported manifest")
    if manifest.get("status")!="accepted":
        raise ValueError("candidate not accepted")
    if manifest.get("comparison")!=">=":
        raise ValueError("threshold comparison mismatch")
    import math
    if not math.isfinite(manifest.get("threshold",float("nan"))):
        raise ValueError("missing finite threshold")
    for name in ("model","input_contract","window_policy","calibration","evaluation"):
        entry=manifest.get("artifacts",{}).get(name,{})
        relative=entry.get("path")
        if not isinstance(relative,str) or not relative:
            raise ValueError("missing artifact: "+name)
        path=(root/relative).resolve()
        if not path.is_relative_to(root):
            raise ValueError("artifact escapes candidate root")
        if sha256(path)!=entry.get("sha256"):
            raise ValueError("artifact hash mismatch: "+name)
    evaluation=json.loads((root/manifest["artifacts"]["evaluation"]["path"]).read_text())
    if not evaluation.get("all_required_gates_passed"):
        raise ValueError("evaluation did not pass")
    if not evaluation.get("required_groups"):
        raise ValueError("no required evaluation groups")
    for name,metrics in evaluation["required_groups"].items():
        if not metrics.get("passes_point_gate"):
            raise ValueError("failed required group: "+name)
    return True
