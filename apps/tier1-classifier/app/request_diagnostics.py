"""Content-free counters and phase timing for internal availability diagnosis."""
from collections import Counter
import threading
import time

class CallTiming:
    def __init__(self):
        self.created=time.monotonic()
        self.started=None
        self.finished=None
        self.lock=threading.Lock()
    def start(self):
        with self.lock:self.started=time.monotonic()
    def finish(self):
        with self.lock:self.finished=time.monotonic()
    def snapshot(self):
        now=time.monotonic()
        with self.lock:started,finished=self.started,self.finished
        return {"inference_started":started is not None,
                "queue_ms":round(((started if started is not None else now)-self.created)*1000,3),
                "inference_ms":round(max(0,(finished if finished is not None else now)-started)*1000,3) if started is not None else 0.0,
                "total_ms":round((now-self.created)*1000,3)}

class RequestDiagnostics:
    def __init__(self):
        self.lock=threading.Lock()
        self.received=0
        self.completed=0
        self.empty=0
        self.failed=Counter()
    def begin(self):
        with self.lock:self.received+=1
    def record(self,reason=""):
        with self.lock:
            if not reason:self.completed+=1
            elif reason=="empty":self.empty+=1
            else:self.failed[reason]+=1
    def snapshot(self):
        with self.lock:
            return {"received":self.received,"completed":self.completed,
                    "empty":self.empty,"failed":dict(self.failed)}
