import json
import pytest
from artifact import sha256,validate_candidate

def test_candidate_must_pass_and_match_exact_pipeline(tmp_path):
    items={}
    for name in ("model","input_contract","window_policy","calibration","evaluation"):
        p=tmp_path/name
        p.write_text(json.dumps({"all_required_gates_passed":True,"required_groups":{"long":{"passes_point_gate":True}}}) if name=="evaluation" else name)
        items[name]={"path":name,"sha256":sha256(p)}
    m={"schema":"jjdguard.judge_candidate/v1","status":"trained_not_accepted","comparison":">=","threshold":0,"artifacts":items}
    with pytest.raises(ValueError,match="not accepted"):validate_candidate(tmp_path,m)
    m["status"]="accepted"
    assert validate_candidate(tmp_path,m)
    (tmp_path/"input_contract").write_text("changed")
    with pytest.raises(ValueError,match="hash mismatch"):validate_candidate(tmp_path,m)

def test_training_success_cannot_replace_evaluation(tmp_path):
    p=tmp_path/"evaluation";p.write_text(json.dumps({"passed":True,"training_loss":0}))
    items={}
    for name in ("model","input_contract","window_policy","calibration","evaluation"):
        q=tmp_path/name
        if not q.exists():q.write_text(name)
        items[name]={"path":name,"sha256":sha256(q)}
    m={"schema":"jjdguard.judge_candidate/v1","status":"accepted","comparison":">=","threshold":0,"artifacts":items}
    with pytest.raises(ValueError,match="evaluation did not pass"):validate_candidate(tmp_path,m)
