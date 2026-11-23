package repository

import (
	"strings"
	"testing"
)

func TestEvidenceRunGroupSpecPrefersExactKeysAndAllowsStrictContentChains(t *testing.T) {
	agent, err := evidenceRunGroupSpec("agent_tasks")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"evidence_run_id", "session_id", "conversation_id", "content_session_id", "runtime_context_id", "request_id"} {
		if !strings.Contains(agent.KeySQL, want) {
			t.Errorf("agent key SQL missing %s: %s", want, agent.KeySQL)
		}
	}
	if !strings.Contains(agent.KeySQL, "content_session:") || !strings.Contains(agent.SourceSQL, "content_session_id") {
		t.Fatalf("agent task must recover exact retained session identity before falling back to request identity: %s", agent.KeySQL)
	}
	if strings.Contains(agent.KeySQL, "content_chain:") || strings.Contains(agent.ConfidenceSQL, "'derived'") {
		t.Fatalf("agent task list must not derive task identity by hashing retained content: key=%s confidence=%s", agent.KeySQL, agent.ConfidenceSQL)
	}
	if !strings.Contains(agent.KeySQL, "runtime_context:") || !strings.Contains(agent.SourceSQL, "runtime_context_id") || !strings.Contains(agent.ConfidenceSQL, "'inferred'") {
		t.Fatalf("agent task must use the bounded runtime context hint before request fallback: key=%s source=%s confidence=%s", agent.KeySQL, agent.SourceSQL, agent.ConfidenceSQL)
	}
	if strings.Index(agent.KeySQL, "content_session_id") > strings.Index(agent.KeySQL, "runtime_context_id") {
		t.Fatalf("a real content-log session must beat the inferred runtime context: %s", agent.KeySQL)
	}
	if !strings.Contains(agent.FilterSQL, "effective_agent_type") {
		t.Fatalf("agent view must exclude non-agent traffic: %s", agent.FilterSQL)
	}

	conversation, err := evidenceRunGroupSpec("ai_conversations")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(conversation.KeySQL, "conversation_id") > strings.Index(conversation.KeySQL, "evidence_run_id") {
		t.Fatalf("conversation view must prefer native web conversation identity: %s", conversation.KeySQL)
	}
	if !strings.Contains(conversation.FilterSQL, "effective_agent_type") || !strings.Contains(conversation.FilterSQL, "= ''") {
		t.Fatalf("conversation view must exclude agent traffic: %s", conversation.FilterSQL)
	}
	if conversation.FilterSQL == agent.FilterSQL {
		t.Fatalf("agent and conversation views must be mutually exclusive: %s", conversation.FilterSQL)
	}

	for _, sql := range []string{agent.KeySQL, conversation.KeySQL} {
		lower := strings.ToLower(sql)
		for _, forbidden := range []string{"date_trunc", "interval", "created_at +", "extract(epoch"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("time-window inference is forbidden (%s): %s", forbidden, sql)
			}
		}
	}
}

func TestEvidenceRunGroupSpecTreatsPromptCacheKeyAsCandidate(t *testing.T) {
	agent, err := evidenceRunGroupSpec("agent_tasks")
	if err != nil {
		t.Fatal(err)
	}
	const candidateGuard = "COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')"
	query := buildEvidenceRunsQuery(agent, []string{"rl.tenant_id = $1"}, 1)
	if !strings.Contains(query, candidateGuard) || !strings.Contains(query, "THEN '' ELSE COALESCE(rl.evidence_run_id, '') END AS evidence_run_id") {
		t.Fatalf("candidate prompt cache keys must enter content-chain derivation: %s", query)
	}
}

func TestEvidenceRunGroupSpecRejectsUnknownView(t *testing.T) {
	if _, err := evidenceRunGroupSpec("surprise"); err == nil {
		t.Fatal("unknown evidence view must fail closed")
	}
}

func TestEvidenceRunListQueryCarriesIntegrityAndTimelineCounts(t *testing.T) {
	spec, _ := evidenceRunGroupSpec("agent_tasks")
	query := buildEvidenceRunsQuery(spec, []string{"rl.tenant_id = $1"}, 1)
	for _, want := range []string{
		"correlation_confidence", "member_request_ids", "request_evidence",
		"response_evidence", "effective_agent_type", "effective_agent_runtime",
		"content_session_id", "FROM content_log_entries WHERE tenant_id = rl.tenant_id",
		"<current_datetime", "request_content_redacted", "runtime_context_id",
	} {
		if !strings.Contains(query, want) {
			t.Errorf("query missing %s", want)
		}
	}
	if !strings.Contains(query, "<system_reminder") || !strings.Contains(query, "^\\s*<current_datetime") {
		t.Fatal("runtime grouping must require the complete observed VS Code envelope")
	}
	if !strings.Contains(query, "session_cl.session_id IS NOT NULL") ||
		!strings.Contains(query, "ORDER BY session_cl.created_at DESC, session_cl.id DESC LIMIT 1") {
		t.Fatal("legacy task recovery must use a bounded request-scoped content session lookup")
	}
	if !strings.Contains(query, "IN (rl.request_id, rl.id)") {
		t.Fatal("request-shaped content session ids must not prevent runtime-context grouping")
	}
	for _, forbidden := range []string{"string_agg(", "transcript_signature", "previous_signature", "content_hash_chain"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("task list must not scan and hash retained transcripts before pagination: found %s", forbidden)
		}
	}
	if !strings.Contains(query, "WHERE tenant_id = $1") && !strings.Contains(query, "rl.tenant_id = $1") {
		t.Fatal("query must remain tenant scoped")
	}
	if strings.Contains(query, `BTRIM(BOTH`) {
		t.Fatal("query must not use TRIM grammar inside BTRIM")
	}
	if !strings.Contains(query, `BTRIM(title_cl.content, '"')`) {
		t.Fatal("query must trim surrounding title quotes with valid PostgreSQL BTRIM syntax")
	}
	if !strings.Contains(query, `<user_query[^>]*>([^<]*)</user_query>`) {
		t.Fatal("task title must prefer the real user_query over the WorkBuddy system envelope")
	}
	if got := strings.Count(query, ") codex_cl"); got != 1 {
		t.Fatalf("Codex correction must probe retained content once, got %d probes", got)
	}
	if !strings.Contains(query, "ORDER BY codex_cl.created_at DESC, codex_cl.id DESC LIMIT 1") {
		t.Fatal("Codex correction must stay parameterized on request_id instead of becoming a global content scan")
	}
	for _, forbidden := range []string{
		"FROM tool_call_logs", "FROM access_content_artifact_links", "FROM retained_artifacts",
	} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("list rows must defer heavy detail statistics until the drawer opens: found %s", forbidden)
		}
	}
	pagedAt := strings.Index(query, "), paged AS (")
	pageMembersAt := strings.Index(query, "), page_members AS (")
	if pagedAt < 0 || pageMembersAt < 0 {
		t.Fatalf("query must retain paged enrichment structure: %s", query)
	}
	pagedSQL := query[pagedAt:pageMembersAt]
	if !strings.Contains(pagedSQL, "COUNT(*) OVER()::int AS total_count") ||
		!strings.Contains(pagedSQL, "ORDER BY ended_at DESC") ||
		!strings.Contains(pagedSQL, "LIMIT $2 OFFSET $3") {
		t.Fatalf("pagination must happen in the lightweight grouped page before enrichment: %s", pagedSQL)
	}
}

func TestPrepareEvidenceRunFilterUsesCorrectedAgentIdentity(t *testing.T) {
	spec, _ := evidenceRunGroupSpec("agent_tasks")
	adjusted, where, args := prepareEvidenceRunFilter("tenant_a", spec, ForwardProxyAccessFilter{AgentType: " OpenAI-Codex "})
	if strings.Contains(strings.Join(where, " "), "rl.agent_type") {
		t.Fatalf("raw agent_type filter would hide corrected historical rows: %v", where)
	}
	if !strings.Contains(adjusted.FilterSQL, "effective_agent_type") || !strings.Contains(adjusted.FilterSQL, "$2") {
		t.Fatalf("effective identity filter missing: %s", adjusted.FilterSQL)
	}
	if len(args) != 2 || args[1] != "openai-codex" {
		t.Fatalf("filter args = %#v", args)
	}
}

func TestPrepareEvidenceRunFilterPushesExactWorkBuddyIdentityIntoCandidate(t *testing.T) {
	spec, _ := evidenceRunGroupSpec("agent_tasks")
	adjusted, where, args := prepareEvidenceRunFilter("tenant_a", spec, ForwardProxyAccessFilter{AgentType: " WorkBuddy "})
	joined := strings.Join(where, " ")
	if !strings.Contains(joined, "rl.agent_type = $2") {
		t.Fatalf("WorkBuddy identity must filter candidate rows with the indexed normalized value: %s", joined)
	}
	if strings.Contains(adjusted.FilterSQL, "$2") {
		t.Fatalf("exact WorkBuddy filter must not be duplicated after enrichment: %s", adjusted.FilterSQL)
	}
	if len(args) != 2 || args[1] != "workbuddy" {
		t.Fatalf("filter args = %#v", args)
	}
}

func TestPrepareEvidenceRunAttentionFilterKeepsPhysicalRiskMembers(t *testing.T) {
	spec, _ := evidenceRunGroupSpec("agent_tasks")
	_, where, args := prepareEvidenceRunFilter("tenant_attention", spec, ForwardProxyAccessFilter{RiskState: "attention"})
	joined := strings.Join(where, " AND ")

	if strings.Contains(joined, "acl_attention_") {
		t.Fatalf("evidence runs must not apply request-list turn representative filtering: %s", joined)
	}
	if !strings.Contains(joined, "COALESCE(rl.risk_state, 'normal') IN ($2, $3)") {
		t.Fatalf("attention evidence runs must retain physical risk members for later run aggregation: %s", joined)
	}
	if len(args) != 3 || args[0] != "tenant_attention" || args[1] != "risk" || args[2] != "blocked" {
		t.Fatalf("attention evidence run args = %#v, want tenant, risk, blocked", args)
	}
}
