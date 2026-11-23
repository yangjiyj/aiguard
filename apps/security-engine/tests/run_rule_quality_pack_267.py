#!/usr/bin/env python3
"""Evaluate the frozen rule corpus against a required control-plane compiled pack.

The pack is strictly parsed by the production loader. Missing fixtures are errors,
not skipped tests. This is offline policy application, not signed HTTP refresh.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import socket
import threading
import time
import urllib.request
import secrets
import uvicorn
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
from app.rule_pack_loader import _build_candidate, _apply_candidate
from test_rule_quality_267 import CASES,engine
from app.main import app
from app.api import check_input

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    data=Path(args.pack).read_bytes()
    pack=json.loads(data)
    candidate=_build_candidate(pack,pack["tenant_id"])
    reports=[]
    for audit in [False,True]:
        with pytest.MonkeyPatch.context() as patch:
            e=engine(patch,audit=audit)
            _apply_candidate(e,candidate,pack["version"])
            patch.setattr(check_input,"engine",e)
            token=secrets.token_hex(24)
            patch.setenv("JJD_INTERNAL_API_SECRET",token)
            sock=socket.socket()
            sock.bind(("127.0.0.1",0))
            url="http://127.0.0.1:"+str(sock.getsockname()[1])
            server=uvicorn.Server(uvicorn.Config(app,log_level="error",lifespan="off"))
            worker=threading.Thread(target=lambda:server.run(sockets=[sock]),daemon=True)
            worker.start()
            deadline=time.monotonic()+5
            while not server.started and worker.is_alive() and time.monotonic()<deadline:
                time.sleep(.01)
            try:
                if not server.started:
                    raise RuntimeError("isolated compiled-policy HTTP engine failed to start")
                rows=[]
                for i,(benign,risk,category) in enumerate(CASES):
                    for kind,text in [("benign",benign),("risk",risk),("benign_then_risk",benign+"\n"+risk),("risk_then_benign",risk+"\n"+benign)]:
                        request=urllib.request.Request(url+"/check-input/",data=json.dumps({
                            "request_id":"compiled-quality-"+str(i)+"-"+kind,"content":text,
                            "skip_semantic":True,"content_source":"user"}).encode(),
                            headers={"Content-Type":"application/json","X-JJDGuard-Internal-Token":token})
                        with urllib.request.urlopen(request,timeout=5) as response:
                            assert response.status == 200
                            result=check_input.CheckInputResponse.model_validate(json.load(response))
                        rows.append({"sample_group":i+1,"kind":kind,"text_sha256":hashlib.sha256(text.encode()).hexdigest(),
                                     "action":result.action,"semantic_status":result.semantic_status,
                                     "semantic_reason":result.semantic_reason,
                                     "findings":[{"category":f.category,"source_rule_id":f.source_rule_id,
                                                  "policy_code":f.policy_code,"action":f.action,
                                                  "confidence":f.confidence,
                                                  "counts_as_security_finding":f.counts_as_security_finding,
                                                  "disposition":f.triage.get("disposition","")}
                                                 for f in result.findings]})
                benign=[r for r in rows if r["kind"]=="benign"]
                risky=[r for r in rows if r["kind"]!="benign"]
                summary={"requests":len(rows),"benign_requests":len(benign),
                         "benign_with_security_finding":sum(any(f["counts_as_security_finding"] for f in r["findings"]) for r in benign),
                         "benign_actions":dict(Counter(r["action"] for r in benign)),
                         "risk_and_mixed_requests":len(risky),
                         "risk_and_mixed_with_security_finding":sum(any(f["counts_as_security_finding"] for f in r["findings"]) for r in risky),
                         "risk_and_mixed_actions":dict(Counter(r["action"] for r in risky))}
                if summary["benign_with_security_finding"]:
                    raise AssertionError("compiled default policy produces benign security findings")
                reports.append({"audit_only":audit,"confidence_gating":True,"source_aware":True,
                                "summary":summary,"results":rows})
            finally:
                server.should_exit=True
                worker.join(timeout=5)
                sock.close()
                if worker.is_alive():
                    raise RuntimeError("isolated compiled-policy HTTP engine failed to stop")
    receipt={"policy_pack_sha256":hashlib.sha256(data).hexdigest(),"policy_pack_version":pack["version"],
             "compiled_matchers":candidate.active_count,"compiled_policies":candidate.policy_count,
             "python":sys.version.split()[0],"transport":"authenticated_loopback_http","reports":reports}
    Path(args.output).write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"sha256":receipt["policy_pack_sha256"],"reports":[r["summary"] for r in reports]},ensure_ascii=False))
if __name__=="__main__":
    main()
