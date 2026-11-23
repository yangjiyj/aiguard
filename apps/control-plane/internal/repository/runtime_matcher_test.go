package repository

import "testing"

func TestNormalizeRuntimeMatcherUsesExecutableTypeAndTrimmedValues(t *testing.T) {
	tests := []struct {
		name     string
		ruleType string
		config   string
		wantOK   bool
		regex    string
		keywords []string
		fields   []string
	}{
		{name: "regex", ruleType: "regex", config: `{"regex":"  foo.+bar  ","keywords":["ignored"]}`, wantOK: true, regex: "foo.+bar"},
		{name: "keyword", ruleType: "keyword", config: `{"keywords":["  secret  "," ","token"]}`, wantOK: true, keywords: []string{"secret", "token"}},
		{name: "field name", ruleType: "field_name", config: `{"field_names":[" password ","", " api_key"]}`, wantOK: true, fields: []string{"password", "api_key"}},
		{name: "blank regex", ruleType: "regex", config: `{"regex":"   "}`, wantOK: false},
		{name: "blank keywords", ruleType: "keyword", config: `{"keywords":[" ",""]}`, wantOK: false},
		{name: "blank fields", ruleType: "field_name", config: `{"field_names":[" "]}`, wantOK: false},
		{name: "domain type is not runtime", ruleType: "prompt_injection", config: `{"keywords":["ignore previous"]}`, wantOK: false},
		{name: "unknown type", ruleType: "shell", config: `{"regex":"rm"}`, wantOK: false},
		{name: "regex mismatch", ruleType: "regex", config: `{"keywords":["secret"]}`, wantOK: false},
		{name: "keyword mismatch", ruleType: "keyword", config: `{"regex":"secret"}`, wantOK: false},
		{name: "field mismatch", ruleType: "field_name", config: `{"keywords":["password"]}`, wantOK: false},
		{name: "invalid json", ruleType: "regex", config: `{`, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeRuntimeMatcher(tc.ruleType, []byte(tc.config))
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want=%v matcher=%+v", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got.Regex != tc.regex || !equalRuntimeStrings(got.Keywords, tc.keywords) || !equalRuntimeStrings(got.FieldNames, tc.fields) {
				t.Fatalf("matcher=%+v want regex=%q keywords=%v fields=%v", got, tc.regex, tc.keywords, tc.fields)
			}
		})
	}
}

func equalRuntimeStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestCapabilityCatalogIdentityUsesPolicyCodeAcrossDisplayDrift(t *testing.T) {
	rule := &Rule{
		PolicyCode:  "builtin.prompt_injection.8894ce9a632bada9",
		RuleType:    "prompt_injection",
		Name:        "客户改过的显示名称",
		Description: "旧版本描述，不应影响稳定目录身份",
		Enabled:     true,
	}
	if !RuleIsCapabilityCatalog(rule) {
		t.Fatal("stable policy code must identify catalog despite display drift")
	}
	rule.PolicyCode = "custom.018f7ec0-0000-7000-8000-000000000001"
	rule.Name = "经典注入指令检测"
	if RuleIsCapabilityCatalog(rule) {
		t.Fatal("customer policy must not become catalog merely by reusing a display name")
	}
}
