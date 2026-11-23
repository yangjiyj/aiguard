package repository

// W1 1.12：参数条件求值器黄金向量。本文件在 control-plane repository 与 gateway-core handler
// 两处逐字相同（仅 package 行不同），保证两侧求值器口径一致。

import (
	"encoding/json"
	"testing"
)

func TestWS1ArgConditionGoldenVectors(t *testing.T) {
	cond := func(path, op, value string) MCPArgCondition {
		c := MCPArgCondition{Path: path, Op: op}
		if value != "" {
			c.Value = json.RawMessage(value)
		}
		return c
	}
	cases := []struct {
		name   string
		conds  []MCPArgCondition
		args   string
		action string
		want   bool
	}{
		{"empty conditions always match", nil, `not json`, "block", true},
		{"eq string", []MCPArgCondition{cond("$.mode", "eq", `"rw"`)}, `{"mode":"rw"}`, "block", true},
		{"eq number normalizes", []MCPArgCondition{cond("$.n", "eq", `1`)}, `{"n":1.0}`, "block", true},
		{"eq number vs string", []MCPArgCondition{cond("$.n", "eq", `1`)}, `{"n":"1"}`, "block", false},
		{"ne", []MCPArgCondition{cond("$.mode", "ne", `"ro"`)}, `{"mode":"rw"}`, "block", true},
		{"in", []MCPArgCondition{cond("$.env", "in", `["prod","staging"]`)}, `{"env":"prod"}`, "block", true},
		{"not_in", []MCPArgCondition{cond("$.env", "not_in", `["prod"]`)}, `{"env":"dev"}`, "block", true},
		{"contains substring", []MCPArgCondition{cond("$.sql", "contains", `"DROP"`)}, `{"sql":"x; DROP TABLE t"}`, "block", true},
		{"contains array element", []MCPArgCondition{cond("$.tags", "contains", `"pii"`)}, `{"tags":["a","pii"]}`, "block", true},
		{"prefix", []MCPArgCondition{cond("$.path", "prefix", `"/etc/"`)}, `{"path":"/etc/hosts"}`, "block", true},
		{"suffix", []MCPArgCondition{cond("$.path", "suffix", `".pem"`)}, `{"path":"/k/a.pem"}`, "block", true},
		{"regex", []MCPArgCondition{cond("$.host", "regex", `"^10\\."`)}, `{"host":"10.0.0.1"}`, "block", true},
		{"gt", []MCPArgCondition{cond("$.rows", "gt", `1000`)}, `{"rows":1001}`, "block", true},
		{"lte false", []MCPArgCondition{cond("$.rows", "lte", `1000`)}, `{"rows":1001}`, "block", false},
		{"exists", []MCPArgCondition{cond("$.force", "exists", "")}, `{"force":false}`, "block", true},
		{"not_exists", []MCPArgCondition{cond("$.force", "not_exists", "")}, `{"x":1}`, "block", true},
		{"missing path is false", []MCPArgCondition{cond("$.path", "prefix", `"/etc/"`)}, `{"x":1}`, "block", false},
		{"quoted key and index", []MCPArgCondition{cond("$['a b'][1]", "eq", `"y"`)}, `{"a b":["x","y"]}`, "block", true},
		{"nested field", []MCPArgCondition{cond("$.opts.recursive", "eq", `true`)}, `{"opts":{"recursive":true}}`, "block", true},
		{"block any value", []MCPArgCondition{cond("$.paths[*]", "prefix", `"/etc/"`)}, `{"paths":["/tmp/a","/etc/b"]}`, "block", true},
		{"allow every value", []MCPArgCondition{cond("$.paths[*]", "prefix", `"/tmp/"`)}, `{"paths":["/tmp/a","/etc/b"]}`, "allow", false},
		{"allow every value ok", []MCPArgCondition{cond("$.paths[*]", "prefix", `"/tmp/"`)}, `{"paths":["/tmp/a","/tmp/b"]}`, "allow", true},
		{"allow empty array is false", []MCPArgCondition{cond("$.paths[*]", "prefix", `"/tmp/"`)}, `{"paths":[]}`, "allow", false},
		{"conditions are AND", []MCPArgCondition{cond("$.a", "eq", `1`), cond("$.b", "eq", `2`)}, `{"a":1,"b":3}`, "block", false},
		{"non-object args", []MCPArgCondition{cond("$.a", "exists", "")}, `[1]`, "block", false},
		{"invalid json args", []MCPArgCondition{cond("$.a", "exists", "")}, `{"a":`, "block", false},
		{"trailing data args", []MCPArgCondition{cond("$.a", "exists", "")}, `{"a":1}{}`, "block", false},
		{"key is case sensitive", []MCPArgCondition{cond("$.Path", "exists", "")}, `{"path":"x"}`, "block", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchMCPArgConditions(tc.conds, tc.args, tc.action); got != tc.want {
				t.Fatalf("MatchMCPArgConditions(%s, %s) = %v, want %v", tc.args, tc.action, got, tc.want)
			}
		})
	}
}

func TestWS1ArgConditionValidation(t *testing.T) {
	bad := [][]MCPArgCondition{
		{{Path: "path", Op: "eq", Value: json.RawMessage(`1`)}},
		{{Path: "$", Op: "eq", Value: json.RawMessage(`1`)}},
		{{Path: "$.a", Op: "bogus", Value: json.RawMessage(`1`)}},
		{{Path: "$.a", Op: "eq"}},
		{{Path: "$.a", Op: "in", Value: json.RawMessage(`"x"`)}},
		{{Path: "$.a", Op: "gt", Value: json.RawMessage(`"x"`)}},
		{{Path: "$.a", Op: "regex", Value: json.RawMessage(`"("`)}},
		{{Path: "$[-1]", Op: "exists"}},
		{{Path: "$['a", Op: "exists"}},
	}
	for i, conds := range bad {
		if err := ValidateMCPArgConditions(conds); err == nil {
			t.Fatalf("case %d must be rejected: %+v", i, conds)
		}
	}
	tooMany := make([]MCPArgCondition, 9)
	for i := range tooMany {
		tooMany[i] = MCPArgCondition{Path: "$.a", Op: "exists"}
	}
	if err := ValidateMCPArgConditions(tooMany); err == nil {
		t.Fatalf("more than 8 conditions must be rejected")
	}
	if err := ValidateMCPArgConditions([]MCPArgCondition{{Path: "$.a[*].b", Op: "prefix", Value: json.RawMessage(`"x"`)}}); err != nil {
		t.Fatalf("valid condition rejected: %v", err)
	}
}
