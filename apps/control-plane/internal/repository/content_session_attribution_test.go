package repository

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// 归属列必须真的落到两支会话查询的最终 SELECT 上。少了任何一列，扫描列数与结果列数
// 就对不上，集成测试会以查询错误暴露；这里先做纯字符串级核对，快速定位回归。
func TestContentSessionAttributionProjectionAppliedToBothQueryPaths(t *testing.T) {
	paths := map[string]string{
		"fast":   buildFastContentSessionListQueryWithAlertOnly(true),
		"scoped": buildContentSessionListQueryScopedWithAlertOnly(false, "", false),
	}
	columns := []string{
		"AS department_id",
		"AS department_name",
		"AS agent_type",
		"AS conversation_id",
		"AS principal_key",
		"AS principal_source",
		"AS principal_source_ip",
		"AS principal_proxy_nat",
	}
	for name, query := range paths {
		for _, column := range columns {
			if !strings.Contains(query, column) {
				t.Fatalf("%s query is missing attribution column %s", name, column)
			}
		}
		if !strings.Contains(query, "dep_fallback") {
			t.Fatalf("%s query is missing the team fallback lateral", name)
		}
		if got := strings.Count(query, ") attr ON TRUE"); got != 1 {
			t.Fatalf("%s query applied the representative-request lateral %d times, want 1", name, got)
		}
		if !strings.Contains(query, "LEFT JOIN teams dep_team") {
			t.Fatalf("%s query is missing the department name join", name)
		}
	}
}

// 扫描顺序靠 total_count 之后的列序，归属列之后不能再有别的东西。
func TestContentSessionAttributionStaysAtSelectTail(t *testing.T) {
	paths := map[string]string{
		"fast":   buildFastContentSessionListQueryWithAlertOnly(true),
		"scoped": buildContentSessionListQueryScopedWithAlertOnly(false, "", false),
	}
	const tail = "AS principal_proxy_nat"
	for name, query := range paths {
		at := strings.Index(query, tail)
		if at < 0 {
			t.Fatalf("%s query lost the attribution tail", name)
		}
		rest := strings.TrimSpace(query[at+len(tail):])
		if !strings.HasPrefix(rest, "FROM page p") {
			t.Fatalf("%s query put something between the attribution columns and FROM page: %q", name, rest[:80])
		}
	}
}

// 归属投影不能改变分页与总数语义：page 的 LIMIT/OFFSET 与 total_count 表达式必须原样保留。
func TestContentSessionAttributionKeepsPaginationSemantics(t *testing.T) {
	fast := buildFastContentSessionListQueryWithAlertOnly(true)
	if !strings.Contains(fast, "LIMIT $4 OFFSET $5") {
		t.Fatal("fast query lost its pagination bounds")
	}
	if !strings.Contains(fast, "0::bigint as total_count") {
		t.Fatal("fast query must not compute an exact total")
	}
	scoped := buildContentSessionListQueryScopedWithAlertOnly(false, "", false)
	if !strings.Contains(scoped, "LIMIT $4 OFFSET $5") {
		t.Fatal("scoped query lost its pagination bounds")
	}
	if !strings.Contains(scoped, "as total_count") {
		t.Fatal("scoped query lost its total expression")
	}
}

// 定位失败时补丁必须原样返回，而不是把列插到错误的位置。
func TestAppendContentSessionAttributionIsNoopWhenAnchorsDrift(t *testing.T) {
	if got, ok := appendContentSessionAttribution("SELECT 1", contentSessionAttributionFastAnchor); ok || got != "SELECT 1" {
		t.Fatalf("drifting query should be returned untouched: ok=%v got=%q", ok, got)
	}
}

// scopeContentSessionListQuery 用 strings.ReplaceAll("cl.tenant_id = $1", ...) 做环境范围
// 重写，任何以 cl 结尾的表别名都会被误伤：别名 acl 的 "acl.tenant_id = $1" 会被改写成
// 带 cl.request_id 的 EXISTS，运行时直接报 missing FROM-clause entry for table "cl"。
// 这条守住「归属子查询不得使用以 cl 结尾的别名」这个不变量。
func TestContentSessionAttributionAliasesSurviveScopedRewrite(t *testing.T) {
	aliasEndingInCl := regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)cl\.`)
	paths := map[string]string{
		"fast":   buildFastContentSessionListQueryWithAlertOnly(true),
		"scoped": buildContentSessionListQueryScopedWithAlertOnly(false, "customer", false),
	}
	for name, query := range paths {
		rewritten := scopeContentSessionListQuery(query, "customer")
		rewritten = scopeContentSessionProjectQuery(rewritten, 7)
		rewritten = addContentSessionDispositionProjection(rewritten)
		for _, hit := range aliasEndingInCl.FindAllStringSubmatch(rewritten, -1) {
			t.Fatalf("%s: alias %q ends in cl and the scope rewrite will mangle it", name, hit[1]+"cl")
		}
		if !strings.Contains(rewritten, "AS principal_proxy_nat") {
			t.Fatalf("%s: attribution projection vanished during the scope rewrite", name)
		}
	}
}

// principal_label 的文案是监管口径，逐字定死。用码位断言而不是肉眼比对，
// 避免形近字被静默写错。
func TestPrincipalLabelConstantsMatchSpecCodepoints(t *testing.T) {
	cases := []struct {
		name  string
		value string
		codes []rune
	}{
		{"user", principalLabelUserPrefix, []rune{0x7528, 0x6237, 0x20}},
		{"upstream", principalLabelUpstreamPrefix, []rune{0x4e0a, 0x6e38, 0x8d26, 0x53f7, 0x20}},
		{"credential", principalLabelCredentialPrefix, []rune{0x4e0a, 0x6e38, 0x51ed, 0x636e, 0x6307, 0x7eb9, 0x20}},
		{"source", principalLabelSourcePrefix, []rune{0x6765, 0x6e90, 0x20, 0x49, 0x50, 0x20}},
		{"nat suffix", principalLabelNATSuffix, []rune{
			0xff08, 0x7ecf, 0x20, 0x4e, 0x41, 0x54, 0xff0c,
			0x4e0d, 0x80fd, 0x5b9a, 0x4f4d, 0x5230, 0x4eba, 0xff09}},
	}
	for _, tc := range cases {
		if got := []rune(tc.value); !reflect.DeepEqual(got, tc.codes) {
			t.Fatalf("%s label codepoints = %#v, want %#v", tc.name, got, tc.codes)
		}
	}
}

func TestPrincipalLabelReadsFourSubjectForms(t *testing.T) {
	t.Setenv("ALERT_NAT_SOURCE_IPS", "")
	cases := []struct {
		name      string
		attribute contentSessionAttribution
		username  string
		want      string
	}{
		{
			name:      "user wins over everything else",
			attribute: contentSessionAttribution{PrincipalKey: "upstream:credential:abc123", SourceIP: "10.0.0.9"},
			username:  "alice",
			want:      principalLabelUserPrefix + "alice",
		},
		{
			name:      "username is trimmed",
			attribute: contentSessionAttribution{SourceIP: "10.0.0.9"},
			username:  "  bob  ",
			want:      principalLabelUserPrefix + "bob",
		},
		{
			name:      "openai account fingerprint",
			attribute: contentSessionAttribution{PrincipalKey: "upstream:openai_account:0f8e7d6c5b4a39281706f5e4d3c2b1a0", SourceIP: "10.0.0.9"},
			want:      principalLabelUpstreamPrefix + "openai:0f8e7d6c",
		},
		{
			name:      "anthropic account fingerprint",
			attribute: contentSessionAttribution{PrincipalKey: "upstream:anthropic_account:8f14e45f-ceea-467a-9c2b-1d3c4e5f6a7b"},
			want:      principalLabelUpstreamPrefix + "anthropic:8f14e45f",
		},
		{
			name:      "credential fingerprint",
			attribute: contentSessionAttribution{PrincipalKey: "upstream:credential:11fb3c8a93d4e5f6"},
			want:      principalLabelCredentialPrefix + "11fb3c8a93d4e5f6",
		},
		{
			name:      "plain source ip",
			attribute: contentSessionAttribution{SourceIP: "203.0.113.7"},
			want:      principalLabelSourcePrefix + "203.0.113.7",
		},
		{
			name:      "forward proxy that lost the source address",
			attribute: contentSessionAttribution{SourceIP: "192.168.56.1", ProxyNAT: true},
			want:      principalLabelSourcePrefix + "192.168.56.1" + principalLabelNATSuffix,
		},
		{
			name: "unknown principal form falls back to source ip",
			attribute: contentSessionAttribution{
				PrincipalKey: "key_deadbeef", SourceIP: "203.0.113.7",
			},
			want: principalLabelSourcePrefix + "203.0.113.7",
		},
		{name: "nothing to attribute", attribute: contentSessionAttribution{}, want: ""},
	}
	for _, tc := range cases {
		if got := tc.attribute.principalLabel(tc.username); got != tc.want {
			t.Fatalf("%s: principalLabel() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPrincipalLabelHonoursNATSourceAllowlist(t *testing.T) {
	attribute := contentSessionAttribution{SourceIP: "192.168.56.1"}
	t.Setenv("ALERT_NAT_SOURCE_IPS", "")
	if got := attribute.principalLabel(""); got != principalLabelSourcePrefix+"192.168.56.1" {
		t.Fatalf("empty allowlist must not mark NAT: %q", got)
	}
	t.Setenv("ALERT_NAT_SOURCE_IPS", " 10.1.1.1 , 192.168.56.1 ,")
	if got := attribute.principalLabel(""); got != principalLabelSourcePrefix+"192.168.56.1"+principalLabelNATSuffix {
		t.Fatalf("allowlisted source ip must be marked NAT: %q", got)
	}
	if got := (contentSessionAttribution{SourceIP: "10.0.0.9"}).principalLabel(""); got != principalLabelSourcePrefix+"10.0.0.9" {
		t.Fatalf("non-allowlisted source ip must stay plain: %q", got)
	}
}

func TestAttributionApplyExposesCustomerFacingFields(t *testing.T) {
	t.Setenv("ALERT_NAT_SOURCE_IPS", "")
	session := map[string]interface{}{"username": "alice", "client_id": "key_secret"}
	contentSessionAttribution{
		DepartmentID: "team-risk", DepartmentName: "Risk", AgentType: "openai-codex",
		ConversationID: "conv-1", PrincipalKey: "upstream:credential:abcdef01", PrincipalSource: "upstream_credential",
		SourceIP: "192.168.56.1", ProxyNAT: true,
	}.apply(session)
	want := map[string]interface{}{
		"department_id":       "team-risk",
		"department_name":     "Risk",
		"agent_type":          "openai-codex",
		"conversation_id":     "conv-1",
		"principal_key":       "upstream:credential:abcdef01",
		"principal_source":    "upstream_credential",
		"principal_source_ip": "192.168.56.1",
		"principal_proxy_nat": true,
		"principal_label":     principalLabelUserPrefix + "alice",
	}
	for key, expected := range want {
		if got := session[key]; got != expected {
			t.Fatalf("session[%q] = %#v, want %#v", key, got, expected)
		}
	}
}
