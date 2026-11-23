import pytest
from decision_margin import decision_margin

def logs(label="normal", split=False):
    values=[('{"instruction_intent":"',[]),(label,[{"token":"attack","logprob":-2.},{"token":"normal","logprob":-.2}]),('","risky_content":false}',[])]
    if split:values=[values[0],("nor",values[1][1]),("mal",[]),values[2]]
    return {"content":[{"token":text,"top_logprobs":top} for text,top in values]}

def test_margin_uses_counterfactual_class_scores_not_reported_confidence():
    assert decision_margin(logs())==pytest.approx(-1.8)

def test_partial_token_or_missing_alternative_is_not_fabricated():
    with pytest.raises(ValueError):decision_margin(logs(split=True))
    v=logs();v["content"][1]["top_logprobs"]=[{"token":"normal","logprob":-.2}]
    with pytest.raises(ValueError):decision_margin(v)

def test_duplicate_intent_is_rejected():
    v=logs();v["content"].append({"token":'{"instruction_intent":"attack"}',"top_logprobs":[]})
    with pytest.raises(ValueError):decision_margin(v)
