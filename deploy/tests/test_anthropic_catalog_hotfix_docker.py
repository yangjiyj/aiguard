#!/usr/bin/env python3
"""Real Docker fixture: only uniquely named, temporary projects are changed."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
PATCH=ROOT/"deploy/hotfix/anthropic-catalog-2.6.14"
BASE="23e9605c83021ba8cf4b6db83aa0d58b6998a4ec"
DOCKER=["docker","--host","unix:///var/run/docker.sock"]
ENV=os.environ.copy();ENV["DOCKER_HOST"]="unix:///var/run/docker.sock";ENV["DOCKER_BUILDKIT"]="0";ENV['CGO_ENABLED']='0'
for key in ["COMPOSE_FILE","COMPOSE_PROJECT_NAME","DOCKER_CONTEXT","DOCKER_TLS_VERIFY","DOCKER_CERT_PATH"]:ENV.pop(key,None)
def run(args,cwd=None,ok=True):
 p=subprocess.run(args,cwd=cwd,env=ENV,text=True,capture_output=True,timeout=180)
 if ok and p.returncode:raise AssertionError("command failed: "+str(args)+"\n"+p.stdout+p.stderr)
 return p
def info(cid):return json.loads(run(DOCKER+["inspect",cid]).stdout)[0]
def wait_health(cid):
 for _ in range(30):
  if info(cid)["State"].get("Health",{}).get("Status")=="healthy":return
  time.sleep(1)
 raise AssertionError("fixture unhealthy")
def sums(pkg):
 names=["manifest.json","hotfix.py","install.sh","rollback.sh","verify.sh","README.md","bin/control-plane-amd64","bin/control-plane-arm64"]
 (pkg/"SHA256SUMS").write_text("".join(hashlib.sha256((pkg/n).read_bytes()).hexdigest()+"  "+n+"\n" for n in names))

with tempfile.TemporaryDirectory(prefix="jjdguard-anthropic-fixture-") as temporary:
 temp=Path(temporary);project="anthrofixture"+uuid.uuid4().hex[:10]
 root=temp/"install";compose=root/"deploy/docker-compose";compose.mkdir(parents=True)
 (root/"VERSION").write_text("2.6.14\n")
 (compose/"manifest.json").write_text(json.dumps({"source_revision":BASE}))
 (compose/"compose-wrapper.sh").write_text('#!/bin/sh\nexec docker compose "$@"\n')
 build=temp/"build";build.mkdir()
 (build/"main.go").write_text('''package main
import("fmt";"net/http")
var marker="original"
func main(){http.HandleFunc("/health",func(w http.ResponseWriter,r *http.Request){fmt.Fprint(w,marker)});http.ListenAndServe(":8081",nil)}
''')
 for marker in ["original","patched"]:
  run(["/usr/local/go/bin/go","build","-ldflags=-X main.marker="+marker,"-o",str(build/marker),str(build/"main.go")])
 (build/"VERSION").write_text("2.6.14\n")
 (build/"Dockerfile").write_text("FROM alpine:3.20\nWORKDIR /app\nCOPY original /app/control-plane\nCOPY VERSION /app/VERSION\nENV FIXTURE_DEFAULT=preserved\nCMD [\"./control-plane\"]\n")
 image="jjdguard/anthropic-fixture:"+project
 run(DOCKER+["build","--network","none","--pull=false","-t",image,str(build)])
 (compose/"docker-compose.offline.yml").write_text('''services:
  control-plane:
    image: '''+image+'''
    environment:
      FIXTURE_SECRET: ${FIXTURE_SECRET}
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8081/health"]
      interval: 1s
      timeout: 1s
      retries: 2
    volumes:
      - fixture-data:/data
  sidecar:
    image: alpine:3.20
    command: ["sleep", "3600"]
volumes:
  fixture-data: {}
''')
 (compose/".env").write_text("FIXTURE_SECRET=synthetic-not-a-customer-secret\n")
 command=DOCKER+["compose","-p",project,"--env-file",str(compose/".env"),"-f",str(compose/"docker-compose.offline.yml")]
 def compose_run(*args,ok=True):return run(command+list(args),compose,ok)
 def cid(service):return compose_run("ps","-q",service).stdout.strip()
 pkg=temp/"package";pkg.mkdir();(pkg/"bin").mkdir()
 for n in ["hotfix.py","install.sh","rollback.sh","verify.sh","README.md"]:shutil.copyfile(PATCH/n,pkg/n)
 (pkg/"manifest.json").write_text(json.dumps({"schema":"jjdguard-anthropic-hotfix.v1","patch_id":"anthropic-catalog-2614-v1","version":"2.6.14","base_revision":BASE,"patched_revision":"fixture-only","binaries":{"amd64":"bin/control-plane-amd64","arm64":"bin/control-plane-arm64"}}))
 for arch in ["amd64","arm64"]:shutil.copyfile(build/"patched",pkg/("bin/control-plane-"+arch))
 sums(pkg)
 def patch(action,*args,ok=True):return run(["python3",str(pkg/"hotfix.py"),action,"--install-dir",str(root),"--health-timeout","10"]+list(args),ok=ok)
 try:
  compose_run("up","-d","--pull","never")
  original_cid=cid("control-plane");wait_health(original_cid)
  original=info(original_cid)["Image"];sidecar=cid("sidecar")
  print(patch("install","--preflight-only").stdout.strip(),flush=True)
  assert not (compose/".jjdguard-hotfix").exists(),"read-only preflight wrote state"
  print(patch("install").stdout.strip(),flush=True)
  patched=info(cid("control-plane"))["Image"];assert patched!=original
  assert cid("sidecar")==sidecar,"unrelated service recreated"
  assert run(DOCKER+["exec",cid("control-plane"),"wget","-qO-","http://127.0.0.1:8081/health"]).stdout=="patched"
  print(patch("verify").stdout.strip(),flush=True)
  state=compose/".jjdguard-hotfix/anthropic-catalog-2614-v1/state.json"
  anchor=json.loads(state.read_text())["original_image"]
  saved=json.loads(state.read_text());saved["phase"]="applying";state.write_text(json.dumps(saved))
  print(patch("install").stdout.strip(),flush=True);assert json.loads(state.read_text())["original_image"]==anchor
  assert json.loads(state.read_text())["phase"]=="installed"
  patch("verify")
  print("PASS interrupted terminal receipt recovered",flush=True)
  compose_run("up","-d","--no-deps","--force-recreate","control-plane");wait_health(cid("control-plane"));assert info(cid("control-plane"))["Image"]==patched
  print("PASS normal Compose recreation preserves patch",flush=True)
  print(patch("rollback").stdout.strip(),flush=True);assert info(cid("control-plane"))["Image"]==original;assert cid("sidecar")==sidecar
  baseline_cid=cid("control-plane")
  (pkg/"bin/control-plane-amd64").write_bytes(b"tamper")
  result=patch("install",ok=False);assert result.returncode!=0 and "校验失败" in result.stderr
  assert cid("control-plane")==baseline_cid
  print("PASS tamper rejected without runtime changes",flush=True)
  (pkg/"bin/control-plane-amd64").write_bytes(b"#!/bin/sh\nexit 1\n");sums(pkg)
  state.unlink() # only a rolled-back fixture receipt; production never deletes state
  result=patch("install",ok=False)
  assert result.returncode!=0 and "已自动回滚" in result.stderr,result.stdout+result.stderr
  assert info(cid("control-plane"))["Image"]==original;wait_health(cid("control-plane"));assert cid("sidecar")==sidecar
  print("PASS failed start auto-rolls back; unrelated service preserved",flush=True)
  shutil.copyfile(build/"patched",pkg/"bin/control-plane-amd64");sums(pkg);state.unlink()
  patch("install");patch("rollback")
  saved=json.loads(state.read_text());saved["phase"]="applying";state.write_text(json.dumps(saved))
  run(DOCKER+["tag",saved["patch_image"],image])
  print(patch("rollback").stdout.strip(),flush=True)
  assert info(cid("control-plane"))["Image"]==original
  print("PASS interrupted retag recovered",flush=True)
  print("PASS Docker installer acceptance",flush=True)
 except BaseException:
  private=compose/".jjdguard-hotfix/anthropic-catalog-2614-v1"
  for name in ["failure.private.json","rollback-failure.private.json","command-failure.private.json"]:
   if (private/name).exists():print(name,(private/name).read_text(),flush=True)
  if (private/"state.json").exists():
   expected=json.loads((private/"state.json").read_text())["runtime_contract"]
   for name in ["patched-contract.private.json","restored-contract.private.json"]:
    if (private/name).exists():
     actual=json.loads((private/name).read_text())
     for key in expected:
      if expected[key]!=actual[key]: print("CONTRACT DIFF",name,key,expected[key],actual[key],flush=True)
  raise
 finally:
  compose_run("down","--volumes","--remove-orphans",ok=False)
  images=run(DOCKER+["image","ls","--format","{{.Repository}}:{{.Tag}}"],ok=False).stdout.splitlines()
  for ref in images:
   if project in ref:run(DOCKER+["image","rm",ref],ok=False)
