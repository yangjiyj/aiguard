import time
import threading
from collections import OrderedDict
from app.bounded_work import execution_budget
from app.detectors.semantic import SemanticDetector
from app.detectors.llm_judge import SemanticOpinion
from app.detectors import semantic as sem


def detector():
    return SemanticDetector(url="http://judge/", model="m", api_key="k", op_timeout=1, total_timeout=2)


def test_repeated_history_reuses_only_exact_completed_windows(monkeypatch):
    d=detector();calls=[]
    def judge(content, deadline, **kw):
        calls.append(content)
        return SemanticOpinion("malicious" if "ATTACK" in content else "benign", "semantic_jailbreak" if "ATTACK" in content else "none", .9, "fixture")
    monkeypatch.setattr(d,"_judge_with_deadline",judge)
    assert d.detect("x"*2000,"input")==[]
    first=len(calls)
    assert d.detect("x"*2000,"input")==[]
    assert len(calls)==first
    out=d.detect("x"*2000+"ATTACK","input")
    assert any(f.get("category")=="semantic_jailbreak" for f in out)
    assert all(isinstance(k,bytes) and len(k)==32 for k in d._window_cache)


def test_cache_is_source_context_and_configuration_scoped(monkeypatch):
    d=detector();calls=[]
    def judge(content, deadline, **kw):
        calls.append(content);return SemanticOpinion("benign","none",.9,"fixture")
    monkeypatch.setattr(d,"_judge_with_deadline",judge)
    for source,context in [("user",None),("tool_result",None),("tool_result",{"user_task":"a"}),("tool_result",{"user_task":"b"})]:
        d._judge_window("same",time.monotonic()+2,source=source,context=context,priority=False)
    assert len(calls)==4
    other=detector();monkeypatch.setattr(other,"_judge_with_deadline",judge)
    other._judge_window("same",time.monotonic()+2,source="user",context=None,priority=False)
    assert len(calls)==5


def test_expiry_eviction_and_failure_do_not_hide_unchecked_content(monkeypatch):
    d=detector();d._window_cache_size=1;calls=[]
    def judge(content, deadline, **kw):
        calls.append(content)
        return sem._TIMEOUT if content=="failure" else SemanticOpinion("benign","none",.9,"fixture")
    monkeypatch.setattr(d,"_judge_with_deadline",judge)
    def run(text):return d._judge_window(text,time.monotonic()+2,source="user",context=None,priority=False)
    run("a");run("b");run("a")
    assert calls==["a","b","a"]
    key=next(iter(d._window_cache));_,op=d._window_cache[key];d._window_cache[key]=(0,op)
    run("a");assert calls.count("a")==3
    run("failure");run("failure");assert calls.count("failure")==2
    assert len(d._window_cache)==1
    assert d._judge_window("a",time.monotonic()-1,source="user",context=None,priority=False) is sem._TIMEOUT


def test_cancellation_during_cache_lookup_is_not_a_completed_verdict(monkeypatch):
    d=detector();cancelled=threading.Event()
    monkeypatch.setattr(d,"_judge_with_deadline",lambda *a,**k: SemanticOpinion("benign","none",.9,"fixture"))
    def run():return d._judge_window("a",time.monotonic()+2,source="user",context=None,priority=False)
    run()
    class CancelOnLookup(OrderedDict):
        def pop(self,*args):
            value=super().pop(*args);cancelled.set();return value
    d._window_cache=CancelOnLookup(d._window_cache)
    with execution_budget(time.monotonic()+2,cancelled):
        assert run() is sem._TIMEOUT


def test_result_finishing_after_cancellation_is_not_cached(monkeypatch):
    d=detector();cancelled=threading.Event()
    def judge(*a,**k):
        cancelled.set();return SemanticOpinion("benign","none",.9,"late")
    monkeypatch.setattr(d,"_judge_with_deadline",judge)
    with execution_budget(time.monotonic()+2,cancelled):
        assert d._judge_window("a",time.monotonic()+2,source="user",context=None,priority=False) is sem._TIMEOUT
    assert not d._window_cache
