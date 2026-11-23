package protection

import "testing"

// 键与原因码常量要和注册表一致：常量指向的项必须存在，原因码必须归到对应的项。
func TestKeyAndReasonConstantsMatchTheRegistry(t *testing.T) {
	for key, reasons := range map[string][]string{
		KeyCloudMetadata: nil, KeyPrivateNetwork: nil, KeyCloudCredential: nil, KeySSHPrivateKey: nil,
		KeyEnvFile: nil, KeySystemSecretFile: nil, KeySecretMount: nil, KeyGitCredential: nil,
		KeySensitiveName: nil, KeySecretEgress: nil, KeyRestrictedFile: nil,
		KeyHighRiskWithoutRule: nil, KeyConfirmWithoutChannel: nil,
		KeyParseRejected:             {ReasonParseRejected},
		KeyIdentityRejected:          {ReasonIdentityRejected},
		KeyToolFailureLoop:           {ReasonToolFailureLoop},
		KeyBurst:                     {ReasonBehaviorBurst},
		KeySkillIdentityInvalid:      nil,
		KeySkillDangerousCommand:     nil,
		KeySkillAdmissionUnavailable: {ReasonSkillAdmissionUnavailable},
	} {
		if _, ok := Lookup(key); !ok {
			t.Errorf("%s is not registered", key)
		}
		for _, reason := range reasons {
			if item, ok := ItemForReason(reason); !ok || item.Key != key {
				t.Errorf("reason %s must belong to %s, got %+v", reason, key, item)
			}
		}
	}
	for cause, key := range PhaseCauseKeys() {
		if _, ok := Lookup(key); !ok {
			t.Errorf("phase cause %s points at unregistered %s", cause, key)
		}
	}
	if PhaseCauseKeys()[CauseAnalyzerHighRisk] != KeyHighRiskWithoutRule || PhaseCauseKeys()[CauseConfirmWithoutChannelFailClosed] != KeyConfirmWithoutChannel {
		t.Fatalf("phase causes=%v", PhaseCauseKeys())
	}
}

// 默认参数直接取注册表：没有这一项或这个参数时为 0。
func TestDefaultIntParamReadsTheRegistry(t *testing.T) {
	if got := DefaultIntParam(KeyToolFailureLoop, ParamWindowSeconds); got != 600 {
		t.Fatalf("tool failure loop window=%d", got)
	}
	if got := DefaultIntParam(KeyToolFailureLoop, ParamThreshold); got != 5 {
		t.Fatalf("tool failure loop threshold=%d", got)
	}
	if got := DefaultIntParam(KeyBurst, ParamWindowSeconds); got != 10 {
		t.Fatalf("burst window=%d", got)
	}
	if DefaultIntParam("agent.unknown", ParamWindowSeconds) != 0 || DefaultIntParam(KeyBurst, ParamThreshold) != 0 {
		t.Fatal("unknown item or parameter must be 0")
	}
}
