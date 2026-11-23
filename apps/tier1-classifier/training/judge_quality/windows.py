"""Bounded, source-offset windows measured AFTER serialization.

The serializer is an injected frozen dependency. This planner never silently
truncates, changes provenance, or treats coverage as a semantic safe verdict.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Window:
    start: int
    end: int
    text: str
    token_count: int

def plan(text, serialize, token_count, *, max_tokens=512, overlap_chars=160, max_windows=128):
    if max_tokens<2 or overlap_chars<0 or max_windows<1:
        raise ValueError("invalid window budget")
    def size(start,end):
        return token_count(serialize(text[start:end]))
    if not text:
        n=size(0,0)
        return {"windows":[Window(0,0,serialize(""),n)] if n<=max_tokens else [],
                "coverage_complete":n<=max_tokens,"covered_chars":0,
                "reason":None if n<=max_tokens else "context_exceeds_budget"}
    if size(0,0)>=max_tokens:
        return {"windows":[],"coverage_complete":False,"covered_chars":0,"reason":"context_exceeds_budget"}
    windows=[]; start=0; covered=0
    while start<len(text) and len(windows)<max_windows:
        end=min(len(text),start+max_tokens*4)
        # Serialization length need not be monotonic: quote/decoding sections
        # can appear/disappear. Binary search is a heuristic only; every emitted
        # window is rechecked and shrunk if needed.
        if size(start,end)>max_tokens:
            lo=start; hi=end
            while lo<hi:
                mid=(lo+hi+1)//2
                if size(start,mid)<=max_tokens: lo=mid
                else: hi=mid-1
            end=lo
        while end>start and size(start,end)>max_tokens:
            end-=1
        if end<=covered:
            # Progress can be impossible with a huge metadata prefix. Surface it.
            if start<covered:
                start=covered
                continue
            break
        rendered=serialize(text[start:end]); nt=token_count(rendered)
        windows.append(Window(start,end,rendered,nt))
        covered=end
        if end==len(text): break
        start=max(start+1,end-overlap_chars)
    return {"windows":windows,"coverage_complete":covered==len(text),
            "covered_chars":covered,
            "reason":None if covered==len(text) else "window_or_context_budget"}


def sentence_spans(text):
    """Split at sentence/paragraph boundaries outside quotes and fenced code."""
    pairs={"「":"」","『":"』","“":"”","‘":"’"}
    stack=[]; fence=False; start=0; i=0; out=[]
    while i<len(text):
        if text.startswith("```",i):
            fence=not fence; i+=3; continue
        c=text[i]
        if not fence:
            if c in pairs: stack.append(pairs[c])
            elif stack and c==stack[-1]:stack.pop()
            elif c=='"':
                if stack and stack[-1]=='"':stack.pop()
                else:stack.append('"')
            if not stack and c in "。！？!?;；\n":
                out.append((start,i+1));start=i+1
        i+=1
    if start<len(text):out.append((start,len(text)))
    return out or [(0,len(text))]

def contextual_plan(text, serialize, token_count, *, max_tokens=512, max_windows=128):
    """Keep a focus sentence and neighboring context, preserving complete quotes.

    This is a candidate planning policy and must be calibrated as part of the
    full pipeline. No sentence is selected or skipped by risk keywords.
    """
    if token_count(serialize(text))<=max_tokens:
        return {"windows":[Window(0,len(text),serialize(text),token_count(serialize(text)))],
                "coverage_complete":True,"covered_chars":len(text),"reason":None}
    atoms=sentence_spans(text)
    windows=[];focus_covered=[];seen=set()
    for index,(a,b) in enumerate(atoms):
        if len(windows)>=max_windows:break
        if token_count(serialize(text[a:b]))>max_tokens:
            # Token budget fallback is visible in evidence; no clipping.
            sub=plan(text[a:b],serialize,token_count,max_tokens=max_tokens,
                     max_windows=max_windows-len(windows),overlap_chars=96)
            windows.extend(Window(a+w.start,a+w.end,w.text,w.token_count) for w in sub["windows"])
            if sub["coverage_complete"]:focus_covered.append(index)
            continue
        lo,hi=index,index
        # Add adjacent complete units only. Unlike arbitrary token overlap, this
        # retains explanation text surrounding quotations when it fits.
        for j in (index-1,index+1):
            if 0<=j<len(atoms):
                na=min(lo,j);nb=max(hi,j)
                if token_count(serialize(text[atoms[na][0]:atoms[nb][1]]))<=max_tokens:
                    lo,hi=na,nb
        start,end=atoms[lo][0],atoms[hi][1]
        if (start,end) not in seen:
            value=serialize(text[start:end])
            windows.append(Window(start,end,value,token_count(value)));seen.add((start,end))
        focus_covered.append(index)
    complete=len(focus_covered)==len(atoms)
    return {"windows":windows,"coverage_complete":complete,
            "covered_chars":len(text) if complete else (atoms[len(focus_covered)-1][1] if focus_covered else 0),
            "reason":None if complete else "window_or_context_budget"}
