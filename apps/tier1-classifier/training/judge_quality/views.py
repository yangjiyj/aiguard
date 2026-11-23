"""Lossless derived views with explicit limits and source offsets.

Decoding creates evidence; it never grants authority or removes the original.
"""
from dataclasses import dataclass
import base64
import binascii
import json
import re
import unicodedata

@dataclass(frozen=True)
class View:
    kind: str
    start: int
    end: int
    text: str

class ViewLimit(ValueError):
    pass

B64=re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
ESC_U=re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
ESC_X=re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
PERCENT=re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
INVISIBLE=re.compile("[\u200b\u200c\u200d\ufeff\u2060]")

def derive(text, *, max_source_chars=131072, max_derived_chars=131072, max_views=128):
    if len(text)>max_source_chars:
        raise ViewLimit("source_budget_exceeded")
    out=[]; total=0
    def add(kind,start,end,value):
        nonlocal total
        if value==text[start:end] or not value:
            return
        total+=len(value)
        if total>max_derived_chars or len(out)>=max_views:
            raise ViewLimit("derived_budget_exceeded")
        out.append(View(kind,start,end,value))
    for m in B64.finditer(text):
        try:
            value=base64.b64decode(m.group(),validate=True).decode("utf-8")
        except (ValueError,UnicodeError,binascii.Error):
            continue
        if any(unicodedata.category(c)=="Cc" and c not in "\n\r\t" for c in value):
            continue
        add("base64",m.start(),m.end(),value)
    for m in ESC_U.finditer(text):
        try:
            value=json.loads('"'+m.group()+'"')
            value.encode("utf-8")  # Reject unpaired surrogate code points.
        except (ValueError,UnicodeError):
            continue
        add("unicode_escape",m.start(),m.end(),value)
    for pattern,kind,prefix in ((ESC_X,"byte_escape","\\x"),(PERCENT,"percent","%")):
        for m in pattern.finditer(text):
            try: value=bytes.fromhex(m.group().replace(prefix,"")).decode("utf-8")
            except (ValueError,UnicodeError): continue
            add(kind,m.start(),m.end(),value)
    if INVISIBLE.search(text):
        add("invisible_removed",0,len(text),INVISIBLE.sub("",text))
    if re.search("[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a]{2,}",text):
        # ASCII width conversion only. Do not apply broad NFKC to ordinary text.
        value="".join(chr(ord(c)-0xfee0) if (0xff10<=ord(c)<=0xff19 or 0xff21<=ord(c)<=0xff3a or 0xff41<=ord(c)<=0xff5a) else c for c in text)
        add("ascii_width",0,len(text),value)
    return out

def evidence(text, **budgets):
    views=derive(text,**budgets)
    return {"original":text,"views":[v.__dict__ for v in views],"coverage_complete":True}

def quote_context(text,start,end):
    # This is syntax metadata, never a benign exemption or proof of authorization.
    pairs=(("「","」"),("『","』"),("“","”"),('"','"'))
    enclosing=[]
    for op,cl in pairs:
        if op==cl:
            points=[m.start() for m in re.finditer(re.escape(op),text)]
            intervals=list(zip(points[::2],points[1::2]))
        else:
            stack=[];intervals=[]
            for i,c in enumerate(text):
                if c==op:stack.append(i)
                elif c==cl and stack:intervals.append((stack.pop(),i))
        enclosing.extend((a,b+1) for a,b in intervals if a<start and end<=b)
    return enclosing


def inspection_evidence(text, max_rounds=3, *, with_source_map=False):
    """Build a coherent view and optionally map each viewed character to source.

    A decoded character points conservatively to the complete original encoded
    span. These offsets are provenance, not a model's localization confidence.
    """
    import hashlib
    original=text;current=text;trace=[];source_map=None
    def finish(status,derived=()):
        out={"original":original,"inspection_text":current,"derived_views":list(derived),
             "normalization_trace":trace,"normalization_status":status}
        if with_source_map:
            out["source_map"]=source_map
        return out
    def original_span(a,b):
        if source_map is None:return a,b
        if a==b:return (source_map[a][0],source_map[a][0]) if a<len(source_map) else (len(original),len(original))
        return source_map[a][0],source_map[b-1][1]
    for depth in range(max_rounds):
        views=derive(current)
        if not views:return finish("inline_complete")
        global_views=[v for v in views if v.kind in {"invisible_removed","ascii_width"}]
        if global_views:
            v=global_views[0]
            before=hashlib.sha256(current.encode()).hexdigest()
            if with_source_map and v.kind=="invisible_removed":
                mapping=source_map if source_map is not None else [(i,i+1) for i in range(len(current))]
                source_map=[span for char,span in zip(current,mapping) if not INVISIBLE.fullmatch(char)]
            current=v.text
            trace.append({"round":depth,"kind":v.kind,"before_sha256":before,
                          "after_sha256":hashlib.sha256(current.encode()).hexdigest()})
            continue
        local=sorted(views,key=lambda v:(v.start,-v.end))
        selected=[];end=0
        for v in local:
            if v.start<end:continue
            if quote_context(current,v.start,v.end) and any(c in v.text for c in '\"「」『』“”‘’'):
                derived=[]
                for w in local:
                    item=dict(w.__dict__)
                    if with_source_map:
                        a,b=original_span(w.start,w.end)
                        item.update(source_start=a,source_end=b,in_original_quote=bool(quote_context(original,a,b)))
                    derived.append(item)
                return finish("lossless_quote_fallback",derived)
            selected.append(v);end=v.end
        pieces=[];mapped=[];start=0
        mapping=source_map
        if with_source_map and mapping is None:
            mapping=[(i,i+1) for i in range(len(current))]
        for v in selected:
            pieces.extend([current[start:v.start],v.text])
            entry={"round":depth,"kind":v.kind,"start":v.start,"end":v.end,
                   "offset_space":"previous_inspection_view"}
            if with_source_map:
                a,b=original_span(v.start,v.end)
                mapped.extend(mapping[start:v.start]);mapped.extend([(a,b)]*len(v.text))
                entry.update(source_start=a,source_end=b)
            trace.append(entry)
            start=v.end
        pieces.append(current[start:])
        if with_source_map:
            mapped.extend(mapping[start:]);source_map=mapped
        current="".join(pieces)
    if derive(current):raise ViewLimit("decoding_depth_exceeded")
    return finish("inline_complete")
