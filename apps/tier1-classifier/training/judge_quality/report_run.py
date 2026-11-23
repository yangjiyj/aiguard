"""Summarize a complete expected population, including absent predictions.

Run in the same environment as evaluation. This reports development evidence;
hashes identify files, not licensing, independent labels or a loaded-model proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
from metrics import evaluate_run

def read_expected(path):
    rows=[json.loads(s) for s in path.read_text().splitlines() if s.strip()]
    for row in rows:
        label=row.get("label",row.get("expect"))
        if label is None:
            label={"confirmed_attack":"attack","benign_context":"benign"}.get(
                row.get("target",{}).get("semantic_state"))
        if label not in ("attack","benign"):
            raise ValueError("input has no supported reference label")
        row["label"]=label
    return rows

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            h.update(block)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--expected",type=Path,required=True)
    ap.add_argument("--predictions",type=Path,required=True)
    ap.add_argument("--threshold",type=float,required=True)
    ap.add_argument("--artifact",type=Path,action="append",default=[])
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args()
    predictions=[json.loads(s) for s in args.predictions.read_text().splitlines() if s.strip()]
    result=evaluate_run(read_expected(args.expected),predictions,args.threshold)
    result.update(schema="jjdguard-development-run/v1",threshold=args.threshold,
                  comparison=">=",evidence_scope="development_not_independent_acceptance",
                  input_file_sha256=sha(args.expected),
                  prediction_file_sha256=sha(args.predictions),
                  artifacts=[{"name":p.name,"sha256":sha(p)} for p in args.artifact])
    with args.out.open("x") as output:
        json.dump(result,output,ensure_ascii=False,indent=2)
        output.write("\n")

if __name__=="__main__":
    main()
