"""Preserve authorization context when building multi-part requests."""
import json

CONTEXT_KEYS=("source","stage","role","user_task","proposed_action")

def context_key(packet):
    ctx=packet.get("context") or {}
    return tuple(str(ctx.get(k) or "") for k in CONTEXT_KEYS)

def compose(rows, request_id):
    if not rows:
        raise ValueError("empty request")
    keys={context_key(r["packet"]) for r in rows}
    if len(keys)!=1:
        raise ValueError("cannot reuse labels across different authorization contexts")
    labels={r["label"] if "label" in r else (
        "attack" if r["target"]["semantic_state"]=="confirmed_attack" else
        "benign" if r["target"]["semantic_state"]=="benign_context" else "uncertain") for r in rows}
    if "uncertain" in labels:
        raise ValueError("uncertain source needs adjudication")
    # Labels remain compositional assertions, not an independent human review.
    # Record every origin and span so composition can be audited and relabeled.
    context=dict(rows[0]["packet"].get("context") or {})
    text=""; spans=[]
    for row in rows:
        value=row["packet"]["untrusted_text"]
        start=len(text); text+=value+"\n"
        spans.append({"id":row["id"],"start":start,"end":start+len(value)})
    return {"id":request_id,"label":"attack" if "attack" in labels else "benign",
            "packet":{"context":context,"untrusted_text":text},
            "origins":spans,"label_basis":"compositional_requires_context_review"}

def unique_origins(rows):
    values={}
    for r in rows:
        sig=json.dumps(r["packet"],sort_keys=True,ensure_ascii=False)
        label=r.get("label") or r.get("target",{}).get("semantic_state")
        if sig in values and values[sig]!=label:
            raise ValueError("identical model input has conflicting labels")
        values[sig]=label
    return len(values)


def near_duplicates(left, right, *, threshold=.55, width=6):
    """Exact shingle Jaccard on all candidate pairs; deterministic, no sampling."""
    import re
    from collections import defaultdict
    def grams(row):
        text=re.sub(r"\s+","",row["packet"]["untrusted_text"])
        if len(text)<width:return {text}
        return {text[i:i+width] for i in range(len(text)-width+1)}
    lg=[grams(r) for r in left]
    inverted=defaultdict(set)
    for i,g in enumerate(lg):
        for token in g:inverted[token].add(i)
    found=[]
    for j,r in enumerate(right):
        rg=grams(r);candidates=set()
        for token in rg:candidates.update(inverted.get(token,()))
        for i in sorted(candidates):
            score=len(lg[i]&rg)/len(lg[i]|rg)
            if score>=threshold:found.append({"left":left[i]["id"],"right":r["id"],"jaccard":score})
    return found


def task_label_conflict(row):
    """Flag one known annotation conflict; this is not an automatic relabeler.

    proposed_action is annotation evidence here, NEVER an inference feature.
    An untrusted source cannot grant authority, but an authenticated user may
    change their own task. Unclear higher-level scope needs adjudication.
    """
    import re
    if row.get("source")!="user" or row.get("label")!="attack":
        return None
    action=str(row.get("proposed_action") or "")
    task_change=re.search(r"replace the assigned task|替换原任务",action,re.I)
    explicit_boundary=re.search(
        r"system prompt|secret|credential|unauthori|security boundary|unrestricted|hidden|"
        r"安全边界|不受约束|未授权|凭据|私密|隐藏|系统提示|密钥",action,re.I)
    if task_change and not explicit_boundary:
        return "user_task_change_without_explicit_higher_authority_violation"
    return None
