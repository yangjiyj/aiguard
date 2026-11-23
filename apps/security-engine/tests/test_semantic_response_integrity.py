import io,json
import pytest
from app.detectors import llm_judge

def valid():
    return {"assessment":"把JSON对象{}作为测试数据","verdict":"benign","category":"none","confidence":.95,"reason":"合法测试"}

def test_braces_inside_assessment_do_not_truncate_the_decision():
    result=llm_judge._parse_semantic(json.dumps(valid(),ensure_ascii=False))
    assert result is not None and result.verdict=="benign"

@pytest.mark.parametrize("value",[float("nan"),float("inf"),95,True])
def test_invalid_confidence_is_not_a_security_verdict(value):
    body=valid();body["assessment"]="正常测试任务";body["confidence"]=value
    assert llm_judge._parse_semantic(json.dumps(body)) is None

def test_duplicate_verdict_is_rejected():
    text='{"verdict":"malicious","verdict":"benign","category":"none","confidence":0.9,"reason":"x"}'
    assert llm_judge._parse_semantic(text) is None

@pytest.mark.parametrize("finish",["length","content_filter"])
def test_legacy_transport_rejects_incomplete_but_parseable_json(monkeypatch,finish):
    response={"choices":[{"finish_reason":finish,"message":{"content":json.dumps(valid())}}]}
    monkeypatch.setattr(llm_judge.urllib.request,"urlopen",lambda *a,**k:io.BytesIO(json.dumps(response).encode()))
    assert llm_judge._post_chat("http://legacy-"+finish+"/",b'{"model":"legacy"}',"k",1) is None

def test_assessment_precedes_classification_in_requested_schema():
    body=llm_judge._build_semantic_payload("text","legacy",json_schema=True)
    schema=body["response_format"]["json_schema"]["schema"]
    assert list(schema["properties"])[0]=="assessment"
    assert schema["required"][0]=="assessment"
