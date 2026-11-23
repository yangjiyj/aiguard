"""Customer capacity is configuration, not a product-sized concurrency ceiling."""
import os
from pathlib import Path
import subprocess
import sys


def test_sixteen_inferences_run_together_without_an_eight_slot_ceiling():
    code = r"""
import threading,time
from app.detectors import semantic as sem
from app.detectors.llm_judge import SemanticOpinion
assert sem._WINDOW_WORKERS == 16
assert sem._JUDGE_WORKERS == 16
barrier=threading.Barrier(16)
lock=threading.Lock()
active=peak=0
def judge(*a,**kw):
    global active,peak
    with lock:
        active+=1;peak=max(peak,active)
    try:barrier.wait(timeout=5)
    finally:
        with lock:active-=1
    return SemanticOpinion('benign','none',.9,'fixture')
sem.judge_semantic=judge
d=sem.SemanticDetector(url='http://fixture.invalid/',model='fixture',api_key='',op_timeout=7,total_timeout=8)
deadline=time.monotonic()+8
plan=[(i,i+1) for i in range(16)]
def inspect(bounds):
    return d._detect_window('unique-window-'+str(bounds[0]),'input',deadline,require_judge=True)
rows=list(d._window_results(plan,inspect,deadline,'input',lambda bounds:bounds))
assert len(rows)==16 and all(result==[] for _,result in rows),rows
assert peak==16,peak
"""
    env = dict(os.environ, SECURITY_SEMANTIC_WINDOW_PARALLELISM="16")
    env.pop("SECURITY_JUDGE_WORKERS", None)
    env.pop("SECURITY_JUDGE_CAPACITY", None)
    result = subprocess.run([sys.executable, "-c", code], env=env, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_customer_window_budget_can_cover_content_beyond_256_windows(monkeypatch):
    from app.detectors.semantic import SemanticDetector
    from app.detectors.llm_judge import SemanticOpinion
    monkeypatch.setenv("SECURITY_SEMANTIC_MAX_WINDOWS", "512")
    d=SemanticDetector(url="http://fixture.invalid/",model="fixture",api_key="",op_timeout=1,total_timeout=10)
    def judge(content, deadline, **kwargs):
        attack="TAIL_ATTACK" in content
        return SemanticOpinion("malicious" if attack else "benign", "semantic_jailbreak" if attack else "none", .9, "fixture")
    monkeypatch.setattr(d,"_judge_with_deadline",judge)
    text="x"*300000+"TAIL_ATTACK"
    out=d.detect(text,"input")
    assert not any(f.get("type")=="semantic_telemetry" for f in out)
    assert any(f.get("category")=="semantic_jailbreak" and f["triage"]["window_end"]==len(text) for f in out)
