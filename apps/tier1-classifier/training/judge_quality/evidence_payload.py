"""Structured evidence for a single semantic judge, independent of model weights."""
import json
from views import evidence, ViewLimit

SOURCES=frozenset({"user","rag","rag_context","retrieval","retrieval_result","web","web_content",
                  "email","attachment","tool_result"})
ROLES=frozenset({"user","assistant","tool","sender","reader","system","developer",""})
STAGES=frozenset({"input","output","agent","tool_result","body","document",""})

def build_payload(text, *, content_source="", task_context=None):
    # Only the caller's explicit metadata is considered. A text marker cannot
    # create or override a trusted source field.
    source=content_source if content_source in SOURCES else "unknown"
    context=task_context if isinstance(task_context,dict) else {}
    if not isinstance(text,str):
        raise TypeError("text must be a string")
    ev=evidence(text)
    return {"context":{"source":source,
         "role":context.get("role","") if context.get("role","") in ROLES else "",
         "stage":context.get("stage","") if context.get("stage","") in STAGES else "",
         "user_task":str(context.get("user_task") or ""),
         "proposed_action":str(context.get("proposed_action") or "")},
         "original":ev["original"],"derived_views":ev["views"]}

def encode_payload(text,**kwargs):
    return json.dumps(build_payload(text,**kwargs),ensure_ascii=False,separators=(",",":"))
