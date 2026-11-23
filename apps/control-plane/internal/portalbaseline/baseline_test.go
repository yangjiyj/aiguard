package portalbaseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 新装模板与基线目标必须一致：模板一改，控制台检查与部署脚本比对口径同步变化。
func TestRealmTemplateMatchesTarget(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", "chat", "keycloak-realm", "realm-jjdguard.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read realm template: %v", err)
	}
	var realm map[string]any
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatalf("parse realm template: %v", err)
	}
	report := Evaluate(realm, time.Now())
	if report.Status != "compliant" {
		for _, item := range report.Items {
			if !item.Compliant {
				t.Errorf("%s: template=%v target=%v", item.Key, item.Current, item.Target)
			}
		}
		t.Fatalf("realm template must satisfy the portal login baseline")
	}
	for _, key := range Keys {
		if realm[key] != Target[key] {
			t.Errorf("%s: template must equal target exactly (template=%v target=%v)", key, realm[key], Target[key])
		}
	}
	if otp, _ := realm["otpPolicyType"].(string); otp != "totp" {
		t.Errorf("realm template must declare the TOTP OTP policy, got %q", otp)
	}
}

func TestEvaluateTreatsStricterValuesAsCompliant(t *testing.T) {
	realm := map[string]any{}
	for k, v := range Target {
		realm[k] = v
	}
	realm["failureFactor"] = float64(3)
	realm["ssoSessionIdleTimeout"] = float64(900)
	realm["waitIncrementSeconds"] = float64(3600)
	realm["passwordPolicy"] = "passwordHistory(5) and length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined) and specialChars(1)"
	if r := Evaluate(realm, time.Now()); r.Status != "compliant" {
		t.Fatalf("stricter settings must pass: %+v", r.Items)
	}
}

func TestEvaluateFlagsLegacyRealm(t *testing.T) {
	// 2.7.1 及以前的模板：sslRequired=none，无密码策略、无显式阈值。
	legacy := map[string]any{"sslRequired": "none", "bruteForceProtected": true, "failureFactor": float64(30)}
	r := Evaluate(legacy, time.Now())
	if r.Status != "not_compliant" || r.Message == "" || r.ApplyHint == "" {
		t.Fatalf("legacy realm must be flagged: %+v", r)
	}
	bad := map[string]bool{}
	for _, item := range r.Items {
		if !item.Compliant {
			bad[item.Key] = true
		}
	}
	for _, key := range []string{"sslRequired", "failureFactor", "passwordPolicy", "ssoSessionIdleTimeout"} {
		if !bad[key] {
			t.Errorf("%s must be reported as non-compliant", key)
		}
	}
	if bad["bruteForceProtected"] {
		t.Error("bruteForceProtected=true already satisfies the baseline")
	}
	weaker := map[string]any{}
	for k, v := range Target {
		weaker[k] = v
	}
	weaker["passwordPolicy"] = "length(8)"
	if r := Evaluate(weaker, time.Now()); r.Status != "not_compliant" {
		t.Fatal("weaker password policy must fail")
	}
}
