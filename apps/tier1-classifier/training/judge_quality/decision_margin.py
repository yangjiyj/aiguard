"""Conditional class log-odds, never an asserted calibrated risk probability."""
import json,math,re

def decision_margin(logprobs):
    tokens=(logprobs or {}).get("content",[])
    text="".join(x["token"] for x in tokens)
    value=json.loads(text)
    if set(value)!={"instruction_intent","risky_content"}:
        raise ValueError("invalid decision fields")
    matches=list(re.finditer(r'"instruction_intent"\s*:\s*"(attack|normal)"',text))
    if len(matches)!=1 or matches[0][1]!=value["instruction_intent"]:
        raise ValueError("ambiguous intent span")
    start,end=matches[0].span(1);offset=0
    for item in tokens:
        stop=offset+len(item["token"])
        if offset==start and stop==end:
            top={p["token"]:p["logprob"] for p in item["top_logprobs"]}
            if not all(k in top and math.isfinite(top[k]) for k in ("attack","normal")):
                raise ValueError("counterfactual class logprob unavailable")
            return top["attack"]-top["normal"]
        offset=stop
    raise ValueError("intent is not one complete token")
