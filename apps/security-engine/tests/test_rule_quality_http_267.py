"""Real loopback HTTP acceptance with the real engine router and synthetic policies.

No production server, external model or credential is contacted. Lifespan is
disabled deliberately: signed control-plane synchronization is tested separately.
"""
import json
import socket
import threading
import time
import urllib.request
import pytest
import uvicorn
from test_rule_quality_267 import CASES, engine

@pytest.mark.parametrize("audit", [False, True])
def test_frozen_samples_over_real_authenticated_http(monkeypatch, audit):
    from app.main import app
    from app.api import check_input, check_output
    local = engine(monkeypatch, audit=audit)
    monkeypatch.setattr(check_input, "engine", local)
    monkeypatch.setattr(check_output, "engine", local)
    token = "synthetic-isolated-quality-token"
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", token)
    sock=socket.socket()
    sock.bind(("127.0.0.1",0))
    address="http://127.0.0.1:"+str(sock.getsockname()[1])
    server=uvicorn.Server(uvicorn.Config(app,log_level="error",lifespan="off"))
    worker=threading.Thread(target=lambda:server.run(sockets=[sock]),daemon=True)
    worker.start()
    deadline=time.monotonic()+5
    while not server.started and worker.is_alive() and time.monotonic()<deadline:
        time.sleep(.01)
    try:
        assert server.started
        requests=0
        for endpoint in ["check-input","check-output"]:
            # Output intentionally does not run prompt-injection intent scanning.
            # Check all five input groups and four output content-safety groups.
            cases=CASES if endpoint=="check-input" else CASES[:4]
            for benign,risk,category in cases:
                for text,is_risk in [(benign,False),(risk,True),(benign+"\n"+risk,True),(risk+"\n"+benign,True)]:
                    data={"request_id":"quality-http-"+str(requests),"content":text,"skip_semantic":True}
                    if endpoint=="check-input": data["content_source"]="user"
                    req=urllib.request.Request(address+"/"+endpoint+"/",data=json.dumps(data).encode(),
                           headers={"Content-Type":"application/json","X-JJDGuard-Internal-Token":token})
                    with urllib.request.urlopen(req,timeout=5) as response:
                        assert response.status==200
                        body=json.load(response)
                    requests+=1
                    assert body["action"] == (("audit" if audit else "block") if is_risk else "allow")
                    assert bool([f for f in body["findings"] if f["counts_as_security_finding"]]) == is_risk
                    if is_risk:
                        assert any(f["category"]==category and f["policy_code"] for f in body["findings"])
                    else:
                        assert body["raw_findings"], "observation evidence survives HTTP"
        assert requests==36
    finally:
        server.should_exit=True
        worker.join(timeout=5)
        sock.close()
    assert not worker.is_alive()
