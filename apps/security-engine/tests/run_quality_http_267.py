#!/usr/bin/env python3
"""Run an integration command against a real, authenticated isolated rule engine.

Example (from apps/security-engine): python tests/run_quality_http_267.py -- /tmp/gateway.test -test.run TestRealEngineHTTP267
Only synthetic block policies are loaded. --semantic-fixture uses controlled
Tier1 HTTP responses with the real client/detector; it is not model readiness. This is not signed policy sync or
model readiness evidence. No background production refresh runs.
"""
import argparse
from contextlib import ExitStack
from dataclasses import replace
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
import uvicorn
from test_rule_quality_267 import engine

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit",action="store_true")
    parser.add_argument("--semantic-fixture",choices=["unavailable","timeout","completed"])
    parser.add_argument("command",nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==["--"] else args.command
    if not command:
        parser.error("integration command is required")
    from app.main import app
    from app.api import check_input,check_output
    with pytest.MonkeyPatch.context() as patch, ExitStack() as fixtures:
        local=engine(patch,audit=args.audit)
        if args.semantic_fixture:
            from app.policy_bindings import CompiledPolicy,CompiledPolicyCapability,PolicySet
            from app.detectors.tier1_client import Tier1Client,BUNDLED_TIER1_URL
            from test_tier1_budget_recovery_267 import upstream,detector
            state=fixtures.enter_context(upstream(patch,
                delay=.15 if args.semantic_fixture=="timeout" else 0,
                status=503 if args.semantic_fixture=="unavailable" else 200))
            client=Tier1Client(url=BUNDLED_TIER1_URL,token="synthetic-tier1",timeout=1)
            sem=detector(client,total=.025 if args.semantic_fixture=="timeout" else 1)
            current=local.snapshot_semantic_runtime()
            patch.setattr(local,"_semantic_runtime",replace(current,
                semantic_master_enabled=True,semantic_input_enabled=True,
                semantic_agent_enabled=True,semantic_detector=sem))
            secret=CompiledPolicy(policy_code="quality.secret.block",policy_id="quality.secret.block",
                policy_name="isolated real secret capability",policy_type="scene_policy",
                scene="data_leak",action="block",enabled=True,binding_mode="any",
                capabilities=[CompiledPolicyCapability(category=cat,
                    supported_stages=["input","output"],allowed_actions=["audit","block"],
                    mask_capable=False) for cat in
                    ["openai_key","anthropic_key","github_token","generic_api_key"]])
            local.load_policies(PolicySet([*local.policies.policies,secret]))
        patch.setattr(check_input,"engine",local)
        patch.setattr(check_output,"engine",local)
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
                raise RuntimeError("isolated engine did not start")
            env=dict(os.environ,JJDGUARD_TEST_ENGINE_URL=url,JJDGUARD_TEST_ENGINE_TOKEN=token)
            return subprocess.run(command,env=env,timeout=180).returncode
        finally:
            server.should_exit=True
            worker.join(timeout=5)
            sock.close()
            if worker.is_alive():
                raise RuntimeError("isolated engine did not stop")
if __name__=="__main__":
    sys.exit(main())
