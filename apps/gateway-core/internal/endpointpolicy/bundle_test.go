package endpointpolicy

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func testBundle(rules []Rule, secrets []SecretPattern) Bundle {
	return Bundle{
		SchemaVersion: "1.0", Version: 5, GeneratedAt: "2026-09-25T00:00:00Z", ModeDefault: "block",
		Rules: rules, SecretPatterns: secrets,
	}
}

func encodedBundle(t *testing.T, bundle Bundle) []byte {
	t.Helper()
	bundle.Checksum = Checksum(bundle)
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeAndValidateRequiresVersionAndCanonicalChecksum(t *testing.T) {
	valid := encodedBundle(t, testBundle(nil, nil))
	if _, err := DecodeAndValidate(valid); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	changed := testBundle(nil, nil)
	changed.Version = 0
	if _, err := DecodeAndValidate(encodedBundle(t, changed)); err == nil {
		t.Fatal("version zero accepted")
	}
	changedChecksum := append([]byte(nil), valid...)
	checksumField := bytes.Index(changedChecksum, []byte(`"checksum":"sha256:`))
	if checksumField < 0 {
		t.Fatal("checksum field missing")
	}
	digestByte := checksumField + len(`"checksum":"sha256:`)
	changedChecksum[digestByte] = '0'
	if valid[digestByte] == '0' {
		changedChecksum[digestByte] = '1'
	}
	if _, err := DecodeAndValidate(changedChecksum); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
}

func TestEvaluateKnownMatchNoMatchAndRiskPrecedence(t *testing.T) {
	bundle := testBundle([]Rule{
		{ID: "audit_rule", Match: Match{ToolType: "system", CommandRegex: `^echo safe$`}, Decision: "audit", Risk: "low", Enabled: true},
		{ID: "block_rule", Match: Match{ToolType: "system", ToolNameRegex: `^Bash$`}, Decision: "block", Risk: "high", Enabled: true},
	}, nil)
	got := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"command": "echo safe"}})
	if !got.Matched || got.Hit.RuleID != "block_rule" || got.Hit.Decision != "block" {
		t.Fatalf("strictest rule not selected: %#v", got)
	}
	miss := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{"file_path": "/tmp/safe"}})
	if miss.Matched || len(miss.Unknown) != 0 {
		t.Fatalf("unrelated tool matched: %#v", miss)
	}
}

func TestEvaluateRedactedArgumentsAndURLFormAreUnknown(t *testing.T) {
	bundle := testBundle([]Rule{{ID: "secret_rule", Match: Match{ArgsSecretPattern: true}, Decision: "confirm", Risk: "high", Enabled: true}}, []SecretPattern{{Kind: "test", Regex: `secret-token`}})
	for _, value := range []string{"<redacted:test>", "%3Credacted%3Atest%3E"} {
		got := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"input": value}})
		if got.Matched || len(got.Unknown) != 1 || !UnknownMayChange(got, "allow", "low") {
			t.Fatalf("redacted value %q was not held as unknown: %#v", value, got)
		}
	}
}

func TestEvaluateHomeGlobIsUnknownOnlyAfterOtherPredicatesMatch(t *testing.T) {
	bundle := testBundle([]Rule{{ID: "home_rule", Match: Match{ToolType: "file", PathGlob: []string{`~/.ssh/id_*`}}, Decision: "confirm", Risk: "high", Enabled: true}}, nil)
	ambiguous := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{"file_path": "/home/any-user/.ssh/id_ed25519"}})
	if ambiguous.Matched || len(ambiguous.Unknown) != 1 {
		t.Fatalf("client home was assumed: %#v", ambiguous)
	}
	// 合流 8.2：路径不可能落在任何家目录下的 ~/x 时是确定不命中，不能让每次读普通文件都“无法评估”。
	for _, path := range []string{"/repo/main.go", "/home/any-user/.ssh/known_hosts", "notes/id_rsa.md"} {
		if unrelated := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{"file_path": path}}); unrelated.Matched || len(unrelated.Unknown) != 0 {
			t.Fatalf("home glob held unrelated path %q as unknown: %#v", path, unrelated)
		}
	}
	for _, path := range []string{"../.ssh/id_rsa", "C:\\Users\\u\\.ssh\\id_rsa", "/home/u/.ssh/<redacted:path>"} {
		if possible := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{"file_path": path}}); possible.Matched || len(possible.Unknown) != 1 {
			t.Fatalf("path %q may be under the client home and must stay unknown: %#v", path, possible)
		}
	}
	otherTool := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"command": "echo safe"}})
	if otherTool.Matched || len(otherTool.Unknown) != 0 {
		t.Fatalf("type mismatch did not exclude home rule: %#v", otherTool)
	}
}

func TestKnownBlockDominatesUnresolvedRule(t *testing.T) {
	bundle := testBundle([]Rule{
		{ID: "secret_rule", Match: Match{ArgsSecretPattern: true}, Decision: "confirm", Risk: "high", Enabled: true},
		{ID: "known_block", Match: Match{ToolType: "system", CommandRegex: `.*`}, Decision: "block", Risk: "high", Enabled: true},
	}, []SecretPattern{{Kind: "test", Regex: `secret-token`}})
	got := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"command": "echo safe", "input": "<redacted:test>"}})
	if !got.Matched || got.Hit.RuleID != "known_block" || len(got.Unknown) != 1 || UnknownMayChange(got, "block", "high") {
		t.Fatalf("known block did not dominate unknown: %#v", got)
	}
}

func TestDecodeAndValidateRejectsUnsupportedMatcherFields(t *testing.T) {
	data := encodedBundle(t, testBundle([]Rule{{ID: "known_rule", Match: Match{ToolType: "system"}, Decision: "audit", Risk: "low", Enabled: true}}, nil))
	mutated := bytes.Replace(data, []byte(`"tool_type":"system"`), []byte(`"tool_type":"system","executable_in":["bash"]`), 1)
	if bytes.Equal(data, mutated) {
		t.Fatal("matcher field fixture replacement failed")
	}
	if _, err := DecodeAndValidate(mutated); err == nil {
		t.Fatal("unsupported matcher field accepted")
	}
}

func TestOfficialControlPlaneBundlesValidateAndMatchFixture(t *testing.T) {
	for _, tc := range []struct {
		file    string
		version int64
	}{
		{file: "testdata/restored-v5.json", version: 5},
		{file: "testdata/desired-v4.json", version: 4},
	} {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := DecodeAndValidate(data)
		if err != nil {
			t.Fatalf("official bundle %s rejected: %v", tc.file, err)
		}
		if bundle.Version != tc.version {
			t.Fatalf("%s version=%d want %d", tc.file, bundle.Version, tc.version)
		}
		if tc.version == 4 {
			got := Evaluate(bundle, ToolInput{Name: "T04PolicyFixture", Type: "system", Arguments: map[string]any{}})
			if !got.Matched || got.Hit.RuleID != "src_13f545bcccc425b51e7e3e69e3d0f767" || got.Hit.Decision != "block" {
				t.Fatalf("v4 official fixture rule mismatch: %#v", got)
			}
		}
	}
}

func TestCommandAndPathRedactionRemainUnknown(t *testing.T) {
	t.Run("command", func(t *testing.T) {
		bundle := testBundle([]Rule{{ID: "command_rule", Match: Match{ToolType: "system", CommandRegex: `shutdown`}, Decision: "confirm", Risk: "high", Enabled: true}}, nil)
		got := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"command": "echo %3Credacted%3E"}})
		if len(got.Unknown) != 1 {
			t.Fatalf("redacted command considered a non-match: %#v", got)
		}
	})
	t.Run("path", func(t *testing.T) {
		bundle := testBundle([]Rule{{ID: "path_rule", Match: Match{ToolType: "file", PathGlob: []string{"**/.ssh/id_*"}}, Decision: "confirm", Risk: "high", Enabled: true}}, nil)
		got := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{"file_path": "%3Credacted%3E"}})
		if len(got.Unknown) != 1 {
			t.Fatalf("redacted path considered a non-match: %#v", got)
		}
	})
}

func TestKnownNonMatchExcludesOtherUnknownArgumentCondition(t *testing.T) {
	bundle := testBundle([]Rule{{
		ID: "command_and_path", Match: Match{ToolType: "system", CommandRegex: `shutdown`, PathGlob: []string{"/safe/**"}}, Decision: "confirm", Risk: "high", Enabled: true,
	}}, []SecretPattern{{Kind: "test", Regex: `secret-token`}})
	got := Evaluate(bundle, ToolInput{Name: "Bash", Type: "system", Arguments: map[string]any{"command": "%3Credacted%3E", "path": "/other/file"}})
	if got.Matched || len(got.Unknown) != 0 {
		t.Fatalf("known path mismatch did not exclude unknown command condition: %#v", got)
	}
}

// 按路径匹配的规则在命中里带上确定命中的参数路径（去重、按出现顺序），供例外按路径层级比对；非路径规则不带。
func TestEvaluatePathRuleHitCarriesMatchedPaths(t *testing.T) {
	bundle := Bundle{Rules: []Rule{
		{ID: "builtin_env_files", Match: Match{ToolType: "file", PathGlob: []string{"**/.env"}}, Decision: "audit", Risk: "high", Enabled: true},
		{ID: "any_file", Match: Match{ToolType: "file"}, Decision: "audit", Risk: "low", Enabled: true},
	}}
	got := Evaluate(bundle, ToolInput{Name: "Read", Type: "file", Arguments: map[string]any{
		"file_path": "/repo/a/.env", "paths": []any{"/repo/README.md", "/repo/b/.env", "/repo/a/.env"},
	}})
	if len(got.Hits) != 2 {
		t.Fatalf("hits=%+v", got.Hits)
	}
	for _, hit := range got.Hits {
		switch hit.RuleID {
		case "builtin_env_files":
			if len(hit.Paths) != 2 || hit.Paths[0] != "/repo/a/.env" || hit.Paths[1] != "/repo/b/.env" {
				t.Fatalf("matched paths=%v", hit.Paths)
			}
		case "any_file":
			if hit.Paths != nil {
				t.Fatalf("a rule without a path glob carries no paths: %v", hit.Paths)
			}
		}
	}
}
