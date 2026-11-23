"""Render real Compose interpolation with synthetic config; never start services."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("name",["docker-compose.yml","docker-compose.offline.yml"])
@pytest.mark.parametrize("workers,capacity",[(None,None),("24","48")])
def test_customer_capacity_and_cluster_endpoint_reach_containers(name,workers,capacity):
    if not shutil.which("docker"):pytest.skip("Docker Compose is required for rendering")
    text=(ROOT/name).read_text()
    env={"PATH":os.environ.get("PATH","/usr/bin:/bin"),"HOME":os.environ.get("HOME","/tmp")}
    env.update({key:"synthetic-fixture-value-only" for key in re.findall(r"\$\{([A-Z0-9_]+):\?",text)})
    env.update(SECURITY_SEMANTIC_WINDOW_PARALLELISM="64",SECURITY_INPUT_WORKERS="64",SECURITY_INPUT_CAPACITY="256",SECURITY_JUDGE_QUEUE_CAPACITY="256",SECURITY_TIER1_MAX_INFLIGHT="32",SECURITY_ENGINE_URL="http://inspection-cluster.example:8000")
    if workers is not None:env["SECURITY_JUDGE_WORKERS"]=workers
    if capacity is not None:env["SECURITY_JUDGE_CAPACITY"]=capacity
    result=subprocess.run(["docker","compose","--env-file","/dev/null","-f",str(ROOT/name),"config","--format","json"],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    services=json.loads(result.stdout)["services"]
    engine=services["security-engine"]["environment"]
    assert engine["SECURITY_SEMANTIC_WINDOW_PARALLELISM"]=="64"
    assert engine["SECURITY_JUDGE_WORKERS"]==(workers or "64")
    assert engine["SECURITY_JUDGE_CAPACITY"]==(capacity or workers or "64")
    assert engine["SECURITY_INPUT_WORKERS"]=="64" and engine["SECURITY_INPUT_CAPACITY"]=="256"
    assert engine["SECURITY_JUDGE_QUEUE_CAPACITY"]=="256" and engine["SECURITY_TIER1_MAX_INFLIGHT"]=="32"
    assert services["gateway-core"]["environment"]["SECURITY_ENGINE_URL"]=="http://inspection-cluster.example:8000"
