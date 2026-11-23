from app.alert_evidence_validation import revalidate

def test_invalid_id_and_git_remote_do_not_remove_real_secret():
    original={"findings":[
        {"category":"id_card_cn","severity":"critical","raw_evidence":"789739705449372800","evidence_context":"sum:789739705449372800"},
        {"category":"email","severity":"low","raw_evidence":"git@gitee.com","evidence_context":"git clone git@gitee.com:org/repo.git"},
        {"category":"openai_key","severity":"critical","raw_evidence":"<preserved>","counts_as_security_finding":True},
    ]}
    revised, severity, reasons = revalidate(original,"critical")
    assert len(reasons)==2 and revised["findings_count"]==1 and severity=="critical"
    assert revised["findings"][2]==original["findings"][2]
    assert "counts_as_security_finding" not in original["findings"][0]

def test_valid_id_is_not_cleared_as_telemetry():
    assert revalidate({"findings":[{"category":"id_card_cn","severity":"critical","raw_evidence":"11010519491231002X","evidence_context":"身份证11010519491231002X"}]},"critical") is None

def test_preserves_original_evidence_and_valid_cooccurring_risk():
    bad={"category":"phone_cn","raw_evidence":"17909487639","evidence_context":"sha256:aaa17909487639bbb","severity":"medium"}
    real={"category":"phone_cn","raw_evidence":"13800138000","evidence_context":"电话13800138000","severity":"high"}
    original={"findings":[bad, real],"findings_count":2}
    revised,severity,reasons=revalidate(original,"high")
    assert severity=="high" and revised["findings_count"]==1
    assert revised["findings"][0]["raw_evidence"]==bad["raw_evidence"]
    assert "counts_as_security_finding" not in original["findings"][0]
    assert revalidate(revised,severity) is None

def test_unavailable_and_unconfirmed_are_not_declared_benign():
    revised,level,_=revalidate({"findings":[{"rule_id":"semantic_tier1_high_confidence","severity":"high"}]},"high")
    assert level=="low"
    assert revised["findings"][0]["evidence_revalidation"]["status"]=="unconfirmed"

def test_missing_evidence_and_real_phone_not_suppressed():
    assert revalidate({"findings":[{"category":"phone_cn","severity":"high"}]},"high") is None
    assert revalidate({"findings":[{"category":"phone_cn","raw_evidence":"13800138000","evidence_context":"abc13800138000ff 电话13800138000","severity":"high"}]},"high") is None
