package repository

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func usageCount(n int64) *int64 { return &n }

type integrationUsageCase struct {
	name, source, raw string
	input, output     *int64
	estimated         bool
	want              IntegrationUsage
}

func integrationUsageCases() []integrationUsageCase {
	actual := func(source string, in, out, read, write *int64) IntegrationUsage {
		return IntegrationUsage{MeasurementState: "actual", UsageSource: source, InputTokens: in, OutputTokens: out, CacheReadInputTokens: read, CacheWriteInputTokens: write}
	}
	unknown := IntegrationUsage{MeasurementState: "uncollected", UsageSource: "unverified"}
	mk := func(name, raw string, in, out *int64, want IntegrationUsage) integrationUsageCase {
		return integrationUsageCase{name, "upstream", `{"usage_source":"upstream","upstream_usage":` + raw + `}`, in, out, false, want}
	}
	cases := []integrationUsageCase{
		mk("native presence", `{"prompt_tokens":10,"completion_tokens":5}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), nil, nil)),
		mk("real zero", `{"prompt_tokens":0,"completion_tokens":0,"prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":0}}`, usageCount(0), usageCount(0), actual("upstream", usageCount(0), usageCount(0), usageCount(0), usageCount(0))),
		mk("missing output", `{"prompt_tokens":10}`, usageCount(10), nil, actual("upstream", usageCount(10), nil, nil, nil)),
		mk("SQL null is not zero", `{"completion_tokens":0}`, nil, usageCount(0), actual("upstream", nil, usageCount(0), nil, nil)),
		mk("null stays missing", `{"prompt_tokens":null,"completion_tokens":5}`, nil, usageCount(5), actual("upstream", nil, usageCount(5), nil, nil)),
		mk("cache miss alone exceeds known input", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":11}`, usageCount(10), usageCount(5), unknown),
		mk("partial cache miss within input", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":7}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), nil, nil)),
		mk("partial cache miss at input bound", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":10}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), nil, nil)),
		mk("partial cache miss zero keeps hit missing", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_miss_tokens":0}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), nil, nil)),
		mk("cache hit and miss match input", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_hit_tokens":3,"prompt_cache_miss_tokens":7}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), usageCount(3), nil)),
		mk("cache hit and miss conflict with input", `{"prompt_tokens":10,"completion_tokens":5,"prompt_cache_hit_tokens":3,"prompt_cache_miss_tokens":8}`, usageCount(10), usageCount(5), unknown),
		mk("combined cache subsets", `{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":3,"cache_write_tokens":2}}`, usageCount(10), usageCount(5), actual("upstream", usageCount(10), usageCount(5), usageCount(3), usageCount(2))),
		mk("Anthropic normalized input", `{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}`, usageCount(15), usageCount(5), actual("upstream", usageCount(15), usageCount(5), usageCount(3), usageCount(2))),
		mk("total only cannot invent components", `{"total_tokens":15}`, usageCount(15), usageCount(0), unknown),
		mk("absent raw fields", `{}`, usageCount(0), usageCount(0), unknown),
		mk("negative SQL counter", `{"completion_tokens":5}`, usageCount(-1), usageCount(5), unknown),
		mk("negative", `{"prompt_tokens":-1}`, usageCount(0), nil, unknown),
		mk("fraction", `{"prompt_tokens":1.5}`, usageCount(1), nil, unknown),
		mk("string", `{"prompt_tokens":"10"}`, usageCount(10), nil, unknown),
		mk("overflow", `{"prompt_tokens":1000000000001}`, nil, nil, unknown),
		mk("invalid details object", `{"prompt_tokens":10,"prompt_tokens_details":"bad"}`, usageCount(10), nil, unknown),
		mk("invalid reasoning", `{"prompt_tokens":10,"completion_tokens":5,"completion_tokens_details":{"reasoning_tokens":6}}`, usageCount(10), usageCount(5), unknown),
		mk("cache sum exceeds input", `{"prompt_tokens":10,"prompt_tokens_details":{"cached_tokens":7,"cache_write_tokens":5}}`, usageCount(10), nil, unknown),
		mk("conflicting input aliases", `{"prompt_tokens":10,"input_tokens":11}`, nil, nil, unknown),
		mk("conflicting output aliases", `{"completion_tokens":5,"output_tokens":6}`, nil, nil, unknown),
		mk("conflicting cache aliases", `{"prompt_tokens":10,"cached_tokens":2,"prompt_tokens_details":{"cached_tokens":3}}`, nil, nil, unknown),
		mk("stored component conflict", `{"prompt_tokens":10,"completion_tokens":5}`, usageCount(11), usageCount(5), unknown),
		mk("total lower than components", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":14}`, usageCount(10), usageCount(5), unknown),
	}
	// Every recognized cache-read spelling must participate in the same
	// native read+miss constraint, including when the original hit is absent.
	for _, alias := range []struct{ name, fields string }{
		{"anthropic_read", `"cache_read_input_tokens":3`},
		{"native_hit", `"prompt_cache_hit_tokens":3`},
		{"cached", `"cached_tokens":3`},
		{"input_cached", `"input_cached_tokens":3`},
		{"prompt_details_cached", `"prompt_tokens_details":{"cached_tokens":3}`},
		{"input_details_cached", `"input_tokens_details":{"cached_tokens":3}`},
		{"input_details_read", `"input_tokens_details":{"cache_read_tokens":3}`},
	} {
		for _, miss := range []string{"7", "8"} {
			want := unknown
			if miss == "7" {
				want = actual("upstream", usageCount(10), usageCount(5), usageCount(3), nil)
			}
			raw := `{"prompt_tokens":10,"completion_tokens":5,` + alias.fields + `,"prompt_cache_miss_tokens":` + miss + `}`
			cases = append(cases, mk("cache alias "+alias.name+" miss "+miss, raw, usageCount(10), usageCount(5), want))
		}
	}
	adjusted := mk("adjusted total keeps native components", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":20}`, usageCount(15), usageCount(5), actual("upstream_total_adjusted", usageCount(10), usageCount(5), nil, nil))
	adjusted.source = "upstream_total_adjusted"
	adjusted.raw = strings.Replace(adjusted.raw, `"usage_source":"upstream"`, `"usage_source":"upstream_total_adjusted"`, 1)
	cases = append(cases, adjusted)
	for _, source := range []string{"admission", "estimated", "gateway", "missing", ""} {
		tc := cases[0]
		tc.name = "untrusted source " + source
		tc.source = source
		tc.want = unknown
		cases = append(cases, tc)
	}
	for _, raw := range []string{`null`, `{}`, `{"usage_source":"upstream","upstream_usage_available":false}`, `{"usage_source":"estimated","upstream_usage":{"prompt_tokens":10}}`, `{"usage_source":"upstream","upstream_usage":[]}`} {
		tc := cases[0]
		tc.name = "missing or conflicting evidence " + raw
		tc.raw = raw
		tc.want = unknown
		cases = append(cases, tc)
	}
	tc := cases[0]
	tc.name = "estimated fact"
	tc.estimated = true
	tc.want = unknown
	cases = append(cases, tc)
	return cases
}

func TestIntegrationUsageNativeEvidence(t *testing.T) {
	for _, tc := range integrationUsageCases() {
		t.Run(tc.name, func(t *testing.T) {
			got := projectIntegrationUsage(tc.source, []byte(tc.raw), tc.input, tc.output, tc.estimated)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%+v want=%+v", got, tc.want)
			}
		})
	}
}

func TestIntegrationUsageJSONNullableAndCountsOnly(t *testing.T) {
	e := IntegrationEvent{ModelID: "native-model", Usage: IntegrationUsage{MeasurementState: "uncollected", UsageSource: "unverified"}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	u := v["usage"].(map[string]any)
	for _, key := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_write_input_tokens"} {
		value, ok := u[key]
		if !ok || value != nil {
			t.Fatalf("%s must be explicit null: %s", key, b)
		}
	}
	if v["model_id"] != "native-model" {
		t.Fatal(string(b))
	}
	for _, bad := range []string{"raw_usage", "prompt", "wallet", "cost", "key_ciphertext"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("unexpected %s", bad)
		}
	}
}
func TestIntegrationUsageExistingDTOContract(t *testing.T) {
	b, err := json.Marshal(IntegrationEvent{ID: "row", RequestID: "request"})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	usage, ok := v["usage"].(map[string]any)
	if !ok {
		t.Fatalf("authorized integration row missing nullable usage contract: %s", b)
	}
	for _, key := range []string{"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_write_input_tokens"} {
		value, ok := usage[key]
		if !ok || value != nil {
			t.Fatalf("missing explicit null %s", key)
		}
	}
	if _, ok := v["model_id"]; !ok {
		t.Fatal("native model_id is absent")
	}
}
