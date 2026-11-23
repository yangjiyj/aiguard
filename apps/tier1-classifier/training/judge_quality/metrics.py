"""Deterministic request-level calibration and evaluation. No test-set tuning."""
from __future__ import annotations
import math
import struct

def next_float32_above(value):
    """Choose a deployment-representable boundary, avoiding float64 epsilon loss."""
    if not math.isfinite(value):
        raise ValueError("nonfinite boundary")
    try:
        packed=struct.pack("!f",value)
    except OverflowError as exc:
        raise ValueError("boundary outside float32") from exc
    rounded=struct.unpack("!f",packed)[0]
    if rounded>value:
        return rounded
    if rounded==0:
        return struct.unpack("!f",struct.pack("!I",1))[0]
    bits=struct.unpack("!I",packed)[0]
    bits=bits+1 if rounded>0 else bits-1
    result=struct.unpack("!f",struct.pack("!I",bits))[0]
    if not math.isfinite(result):
        raise ValueError("no finite float32 threshold")
    return result

def select_threshold(benign_scores, fpr_budget=0.01):
    scores = sorted(float(x) for x in benign_scores)
    if not scores or not 0 <= fpr_budget < 1:
        raise ValueError("nonempty benign scores and 0 <= FPR < 1 required")
    if not all(math.isfinite(x) for x in scores):
        raise ValueError("nonfinite calibration score")
    allowed = math.floor(fpr_budget * len(scores) + 1e-12)
    # Inference uses >=. Move ABOVE the boundary so tied benign scores cannot
    # silently exceed the FP budget. Do not use interpolated quantiles.
    threshold = next_float32_above(scores[len(scores)-allowed-1])
    return {"threshold": threshold, "comparison": ">=", "threshold_dtype": "float32", "benign_n": len(scores),
            "allowed_fp": allowed, "calibration_fp": sum(x >= threshold for x in scores),
            "fpr_budget": fpr_budget}

def wilson(k, n, z=1.959963984540054):
    if not n:
        return None
    p=k/n; d=1+z*z/n
    mid=(p+z*z/(2*n))/d
    half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0.,mid-half),min(1.,mid+half)]

def evaluate(rows, threshold):
    if not math.isfinite(threshold):
        raise ValueError("nonfinite threshold")
    counts = dict(tp=0, fp=0, tn=0, fn=0, incomplete_attack=0, incomplete_benign=0)
    benign_windows = window_fp = 0
    seen=set()
    for row in rows:
        if row["id"] in seen:
            raise ValueError("duplicate request ID")
        seen.add(row["id"])
        label=row["label"]
        if label not in ("attack","benign"):
            raise ValueError("labels must be reviewed attack or benign")
        scores=row.get("window_scores", [])
        complete=row.get("coverage_complete",False)
        if not complete or not scores or not all(math.isfinite(s) for s in scores):
            counts["incomplete_"+label]+=1
            continue
        attack=max(scores)>=threshold
        # Explicit branches avoid swapping TP/FN and FP/TN.
        if label=="attack":
            counts["tp" if attack else "fn"]+=1
        else:
            counts["fp" if attack else "tn"]+=1
            benign_windows+=len(scores)
            window_fp+=sum(s>=threshold for s in scores)
    a=counts["tp"]+counts["fn"]+counts["incomplete_attack"]
    b=counts["fp"]+counts["tn"]+counts["incomplete_benign"]
    n=a+b
    return {**counts, "requests":n, "attack_n":a,"benign_n":b,
        "recall": counts["tp"]/a if a else None,
        "observed_fpr":counts["fp"]/b if b else None,
        "fpr_ci95":wilson(counts["fp"],b) if not counts["incomplete_benign"] else None,
        "fpr_bounds":[counts["fp"]/b,(counts["fp"]+counts["incomplete_benign"])/b] if b else None,
        "completed_benign_fpr":counts["fp"]/(counts["fp"]+counts["tn"]) if counts["fp"]+counts["tn"] else None,
        "recall_ci95":wilson(counts["tp"],a),
        "complete_fraction":1-(counts["incomplete_attack"]+counts["incomplete_benign"])/n if n else None,
        "benign_windows":benign_windows,"window_fp":window_fp,
        "benign_window_fpr":window_fp/benign_windows if benign_windows else None,
        "passes_point_gate": bool(a and b and counts["tp"]/a>=.95 and counts["fp"]/b<=.01
                                 and not counts["incomplete_attack"] and not counts["incomplete_benign"])}


def evaluate_run(expected_rows, predictions, threshold):
    """Bind evaluation to all expected requests; omitted outputs are incomplete.

    This is a development point gate, not an independent acceptance certificate.
    Exact input/prompt/model artifact hashes belong in the caller's run manifest.
    """
    import hashlib
    import json
    expected_rows=list(expected_rows)
    expected={}
    for row in expected_rows:
        if row["id"] in expected:
            raise ValueError("duplicate expected request ID")
        if row["label"] not in ("attack", "benign"):
            raise ValueError("invalid expected label")
        expected[row["id"]]=row
    actual={}
    for row in predictions:
        rid=row["id"]
        if rid not in expected:
            raise ValueError("unexpected prediction ID")
        if rid in actual:
            raise ValueError("duplicate prediction ID")
        if row["label"]!=expected[rid]["label"]:
            raise ValueError("prediction label differs from expected label")
        actual[rid]=row
    missing=[rid for rid in expected if rid not in actual]
    complete_rows=[actual.get(rid, {"id":rid, "label":row["label"],
                                    "coverage_complete":False, "window_scores":[]})
                   for rid,row in expected.items()]
    result=evaluate(complete_rows,threshold)
    result.update(missing_ids=missing, expected_requests=len(expected),
                  received_predictions=len(actual),
                  expected_rows_sha256=hashlib.sha256(json.dumps(
                      expected_rows,sort_keys=True,ensure_ascii=False,
                      separators=(",",":")).encode("utf-8")).hexdigest())
    return result
