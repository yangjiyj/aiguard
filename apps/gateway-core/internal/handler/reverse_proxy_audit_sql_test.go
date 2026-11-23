package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

func TestReverseProxyAccessUpsertWritesResolvedAccessType(t *testing.T) {
	query := reverseProxyAccessUpsertSQL()

	if !strings.Contains(query, "proxy_access_type_resolved") {
		t.Fatalf("reverse proxy access upsert should write proxy_access_type_resolved:\n%s", query)
	}
	if !strings.Contains(query, "proxy_access_type_resolved = EXCLUDED.proxy_access_type_resolved") {
		t.Fatalf("reverse proxy access upsert should refresh resolved access type on conflict:\n%s", query)
	}
}

func TestConfiguredDeploymentEnvironmentScopeUsesTrustedEnvironment(t *testing.T) {
	t.Setenv("GATEWAY_ENVIRONMENT_SCOPE", " CUSTOMER ")
	if got := configuredDeploymentEnvironmentScope(); got != "customer" {
		t.Fatalf("configured scope = %q, want customer", got)
	}
	t.Setenv("GATEWAY_ENVIRONMENT_SCOPE", "from-request-header")
	if got := configuredDeploymentEnvironmentScope(); got != "legacy-unclassified" {
		t.Fatalf("untrusted configured scope = %q, want legacy-unclassified", got)
	}
}

// TestReverseProxyPrincipalKey：反代无用户归属，principal_key = COALESCE(client_id, source_ip)，
// client_id（caller_ 脱敏身份）优先，来源 IP 兜底（契约6）。
func TestReverseProxyPrincipalKey(t *testing.T) {
	cases := []struct {
		record reverseProxyAuditRecord
		want   string
	}{
		{reverseProxyAuditRecord{ClientID: "caller_abc", SourceIP: "1.2.3.4"}, "caller_abc"},
		{reverseProxyAuditRecord{SourceIP: "1.2.3.4"}, "1.2.3.4"},
		{reverseProxyAuditRecord{ClientID: "   ", SourceIP: "1.2.3.4"}, "1.2.3.4"},
		{reverseProxyAuditRecord{}, ""},
	}
	for i, c := range cases {
		if got := reverseProxyPrincipalKey(c.record); got != c.want {
			t.Fatalf("case %d: principal_key want %q got %q", i, c.want, got)
		}
	}
}

func TestReverseProxyContentInsertSQLWritesConversationTriplet(t *testing.T) {
	query := reverseProxyContentInsertSQL()
	for _, col := range []string{"conversation_id", "section_id", "model"} {
		if !strings.Contains(query, col) {
			t.Fatalf("反代 access_content_logs INSERT 缺列 %s（反代流量首次获得 SP4 分组能力靠它）:\n%s", col, query)
		}
	}
	if !strings.Contains(query, "conversation_id = NULLIF(EXCLUDED.conversation_id, '')") {
		t.Fatalf("冲突更新应按 NULLIF 口径刷新 conversation_id（与 C 路 proxy-server audit.go 同款）:\n%s", query)
	}
}

func TestBuildReverseProxyRetentionProjectionUsesLatestUserTurn(t *testing.T) {
	record := reverseProxyAuditRecord{
		TenantID:   "tenant_default",
		RequestID:  "req-turn-1",
		AgentType:  "codex",
		TargetHost: "api.example.com",
		TargetPath: "/v1/responses",
	}
	parsed := aimsg.ParsedChat{
		Model:        "gpt-5.2-codex",
		SystemText:   "trusted runtime",
		FirstUserSHA: aimsg.ContentSHA256Hex("最初问题"),
		LastUserText: "继续实现",
		LastUserSHA:  aimsg.ContentSHA256Hex("继续实现"),
	}
	projection := buildReverseProxyRetentionProjection(
		record, parsed, true,
		`{"instructions":"必须调用 Skill","input":"继续实现"}`,
		"[reasoning] private thought\n正常最终回答\n<oai-mem-citation><rollout_ids>private</rollout_ids></oai-mem-citation>",
	)
	if projection.RequestText != "继续实现" {
		t.Fatalf("请求留证只能展示最后用户原话: %+v", projection)
	}
	if projection.ResponseText != "正常最终回答" {
		t.Fatalf("回答留证错误: %+v", projection)
	}
	if strings.Contains(projection.ResponseText, "reasoning") || strings.Contains(projection.ResponseText, "rollout_ids") {
		t.Fatalf("反代回答不得暴露模型内部内容: %+v", projection)
	}
	if projection.SectionID != aimsg.ContentSHA256Hex("继续实现") {
		t.Fatalf("section_id 必须绑定当前用户回合: %+v", projection)
	}
	if projection.ConversationID == "" || projection.Model != "gpt-5.2-codex" ||
		projection.DecoderVersion != "v2" {
		t.Fatalf("结构化留证字段缺失: %+v", projection)
	}

	sameTurn := buildReverseProxyRetentionProjection(record, parsed, true, "不同协议整包", "最终回答 2")
	if sameTurn.ConversationID != projection.ConversationID || sameTurn.SectionID != projection.SectionID {
		t.Fatalf("同一用户回合的物理请求必须得到相同 turn 键: first=%+v same=%+v", projection, sameTurn)
	}
	parsed.LastUserText = "下一回合"
	parsed.LastUserSHA = aimsg.ContentSHA256Hex(parsed.LastUserText)
	nextTurn := buildReverseProxyRetentionProjection(record, parsed, true, "", "")
	if nextTurn.ConversationID != projection.ConversationID || nextTurn.SectionID == projection.SectionID {
		t.Fatalf("新用户回合只应改变 section_id: first=%+v next=%+v", projection, nextTurn)
	}
}

func TestBuildReverseProxyRetentionProjectionRequiresUserForTurnKey(t *testing.T) {
	record := reverseProxyAuditRecord{
		TenantID:   "tenant_default",
		ClientID:   "caller_a",
		AgentType:  "codex",
		TargetHost: "api.example.com",
		TargetPath: "/v1/responses",
	}
	parsed := aimsg.ParsedChat{SystemText: "trusted background instructions"}
	projection := buildReverseProxyRetentionProjection(record, parsed, true, "", "")
	if projection.ConversationID != "" || projection.SectionID != "" {
		t.Fatalf("没有真实用户消息的后台任务不得生成 turn 键: %+v", projection)
	}
}

func TestBuildReverseProxyRetentionProjectionIsolatesCallers(t *testing.T) {
	parsed := aimsg.ParsedChat{
		SystemText:   "trusted runtime",
		FirstUserSHA: aimsg.ContentSHA256Hex("相同问题"),
		LastUserText: "相同问题",
		LastUserSHA:  aimsg.ContentSHA256Hex("相同问题"),
	}
	base := reverseProxyAuditRecord{
		TenantID: "tenant_default", AgentType: "codex",
		TargetHost: "api.example.com", TargetPath: "/v1/responses",
	}
	a := base
	a.ClientID = "shared_client"
	a.SessionID = "session_a"
	a.SourceIP = "10.0.0.1"
	b := base
	b.ClientID = "shared_client"
	b.SessionID = "session_b"
	b.SourceIP = "10.0.0.1"
	projectionA := buildReverseProxyRetentionProjection(a, parsed, true, "", "回答")
	projectionB := buildReverseProxyRetentionProjection(b, parsed, true, "", "回答")
	if projectionA.ConversationID == "" || projectionA.ConversationID == projectionB.ConversationID {
		t.Fatalf("共享凭据的不同会话不得合并: a=%+v b=%+v", projectionA, projectionB)
	}
	b.SessionID = a.SessionID
	projectionSame := buildReverseProxyRetentionProjection(b, parsed, true, "", "回答")
	if projectionSame.ConversationID != projectionA.ConversationID {
		t.Fatalf("相同调用方与会话应保持稳定: a=%+v same=%+v", projectionA, projectionSame)
	}
}

func TestBuildReverseProxyRetentionProjectionParseFailDoesNotExposeEnvelope(t *testing.T) {
	record := reverseProxyAuditRecord{TenantID: "tenant_default", TargetHost: "api.example.com", TargetPath: "/v1/responses"}
	projection := buildReverseProxyRetentionProjection(
		record, aimsg.ParsedChat{}, false,
		`{"instructions":"<EXTREMELY-IMPORTANT>必须调用 Skill</EXTREMELY-IMPORTANT>"}`,
		"",
	)
	if projection.RequestText != "" || projection.ConversationID != "" || projection.SectionID != "" {
		t.Fatalf("已知 LLM 协议解析失败不得把内部整包当用户内容: %+v", projection)
	}
	if projection.DecoderVersion != "v1" {
		t.Fatalf("解析失败必须保留 decoder_version=v1 遥测: %+v", projection)
	}
}

func TestBuildReverseProxyMessageRows(t *testing.T) {
	record := reverseProxyAuditRecord{TenantID: "tenant_default", RequestID: "req-rows-1", InputTokens: 42}
	msgs := []aimsg.ConvMessage{
		{Role: "system", Source: aimsg.SourceSystemPrompt, Content: "系统提示词"},
		{Role: "user", Source: aimsg.SourceUser, Content: "   "},
		{Role: "user", Source: aimsg.SourceUser, Content: "用户提问 sk-live1234567890ABCDEF"},
		{
			Role:    "user",
			Source:  aimsg.SourceUser,
			Content: "You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another LLM that will resume the task.\n\nInclude:\n- Current progress and key decisions made\n- Important context, constraints, or user preferences\n- What remains to be done",
		},
	}
	rows := buildReverseProxyMessageRows(record, msgs)
	if len(rows) != 1 {
		t.Fatalf("内容留证只能保留当前用户原话: %+v", rows)
	}
	if rows[0].Role != "user" {
		t.Fatalf("系统提示和工具中间内容不得进入默认内容留证: %+v", rows)
	}
	// 逐条走既有脱敏（sk- 密钥打码）。
	if strings.Contains(rows[0].Content, "sk-live1234567890ABCDEF") || !strings.Contains(rows[0].Content, "<redacted:secret>") {
		t.Fatalf("消息内容未脱敏: %q", rows[0].Content)
	}
	if rows[0].Tokens != 42 {
		t.Fatalf("tokens 归属错误: %+v", rows)
	}
	again := buildReverseProxyMessageRows(record, msgs)
	if rows[0].LogID != again[0].LogID || rows[0].LogID == "" {
		t.Fatalf("LogID 需确定且唯一: %+v", rows)
	}
}

func TestBuildReverseProxyRetentionProjectionSuppressesPureOrchestratorTask(t *testing.T) {
	record := reverseProxyAuditRecord{
		TenantID:   "tenant_default",
		RequestID:  "req-internal-task",
		AgentType:  "openai-codex",
		TargetHost: "api.example.com",
		TargetPath: "/v1/responses",
	}
	parsed := aimsg.ParsedChat{Model: "gpt-5-codex"}
	projection := buildReverseProxyRetentionProjection(
		record, parsed, true, "", "internal background result",
	)
	if projection.RequestText != "" || projection.ResponseText != "" ||
		projection.ConversationID != "" || projection.SectionID != "" {
		t.Fatalf("纯编排任务不得进入客户内容留证: %+v", projection)
	}
}

func TestReverseProxyClineHistoryAggregation(t *testing.T) {
	record := reverseProxyAuditRecord{TenantID: "tenant", ClientID: "caller", AgentType: "cline", TargetHost: "api.example.com", TargetPath: "/v1/chat/completions"}
	parse := func(mode string) aimsg.ParsedChat {
		text := "<task>检查项目</task>\n\n# task_progress RECOMMENDED\n<environment_details>\n" + mode + "\n</environment_details>"
		body, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": text}}})
		parsed, ok := aimsg.ParseOpenAIChatRequest(body)
		if !ok {
			t.Fatal("fixture failed")
		}
		return parsed
	}
	a := buildReverseProxyRetentionProjection(record, parse("ACT MODE"), true, "", "回答")
	b := buildReverseProxyRetentionProjection(record, parse("PLAN MODE"), true, "", "回答")
	if a.ConversationID == "" || a.ConversationID != b.ConversationID {
		t.Fatal("reverse proxy split Cline history")
	}
	record.ClientID = "another-caller"
	c := buildReverseProxyRetentionProjection(record, parse("ACT MODE"), true, "", "回答")
	if a.ConversationID == c.ConversationID {
		t.Fatal("reverse proxy merged callers")
	}
}
