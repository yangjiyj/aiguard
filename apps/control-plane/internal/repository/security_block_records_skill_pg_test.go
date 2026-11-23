package repository

import (
	"context"
	"testing"
)

// 现场：Skill 调用被拦截时同一工具调用写两条事件——网关的 tool_attempt_blocked（带命令与依据）
// 和控制面的 skill_invocation_risk（只有 Skill 名）。后者在阻断记录里是一条几乎全空的重复行；
// 同一请求已有工具调用阻断记录时不再单独列出，没有配对记录的仍然列出。
func TestSkillInvocationRiskDuplicatingAToolBlockIsNotListedTwice(t *testing.T) {
	repo, pool := newBlockRecordsTestRepo(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO security_events (id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,created_at) VALUES
		('evt_skill_tool','req-skill','t1','p1','u1','tool_attempt_blocked','critical','block',
		 '{"stage":"tool","block":{"block_id":"evt_skill_tool","layer":"agent_tool","detail":"Skill · rm -rf /tmp/demo"},"findings":[{"type":"tool_attempt_blocked","action":"block","evidence_reason":"analyzer_high_risk_block"}]}', NOW() + interval '1 minute'),
		('evt_skill_dup','req-skill','t1','p1',NULL,'skill_invocation_risk','high','block',
		 '{"stage":"tool","summary":"Skill 调用风险观察","skill_name":"demo-debug","effective_decision":"block"}', NOW() + interval '1 minute'),
		('evt_skill_alone','req-skill-alone','t1','p1',NULL,'skill_invocation_risk','high','confirm',
		 '{"stage":"tool","summary":"Skill 调用风险观察","skill_name":"other-skill","effective_decision":"confirm"}', NOW() + interval '2 minutes')`); err != nil {
		t.Fatal(err)
	}
	records, total, err := repo.ListBlockRecords(ctx, "t1", SecurityBlockRecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, record := range records {
		ids[record.BlockID] = true
	}
	if ids["evt_skill_dup"] || !ids["evt_skill_tool"] || !ids["evt_skill_alone"] || total != len(records) || total != 5 {
		t.Fatalf("want tool block + unpaired skill only (5 total), got total=%d ids=%v", total, ids)
	}
	if _, err := repo.GetBlockRecord(ctx, "t1", "evt_skill_dup"); err != nil {
		t.Fatalf("按编号直接查询仍应能打开这条记录: %v", err)
	}
}
