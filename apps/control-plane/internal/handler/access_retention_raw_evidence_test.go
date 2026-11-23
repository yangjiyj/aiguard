package handler

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

func turnsWithRequests(groups ...[]string) []types.AccessRetentionTurnInfo {
	turns := make([]types.AccessRetentionTurnInfo, 0, len(groups))
	for _, ids := range groups {
		turns = append(turns, types.AccessRetentionTurnInfo{RequestIDs: ids})
	}
	return turns
}

func TestFillBlockedInputEvidenceRequestIDsKeepsOrderAndOnlyListsEvidence(t *testing.T) {
	turns := turnsWithRequests([]string{"r1", "r2", "r3"}, []string{"r4"}, []string{"r5", "r6"})
	fillBlockedInputEvidenceRequestIDs(turns, map[string]struct{}{"r3": {}, "r1": {}, "r6": {}})
	if !reflect.DeepEqual(turns[0].BlockedInputEvidenceRequestIDs, []string{"r1", "r3"}) {
		t.Fatalf("应保持 request_ids 的先后顺序且只列有留证的：%v", turns[0].BlockedInputEvidenceRequestIDs)
	}
	if len(turns[1].BlockedInputEvidenceRequestIDs) != 0 {
		t.Fatalf("没有请求有留证的回合应为空：%v", turns[1].BlockedInputEvidenceRequestIDs)
	}
	if !reflect.DeepEqual(turns[2].BlockedInputEvidenceRequestIDs, []string{"r6"}) {
		t.Fatalf("turn3=%v", turns[2].BlockedInputEvidenceRequestIDs)
	}
}

func TestFillBlockedInputEvidenceRequestIDsWithEmptySetLeavesAllEmpty(t *testing.T) {
	turns := turnsWithRequests([]string{"r1"}, []string{"r2"})
	fillBlockedInputEvidenceRequestIDs(turns, map[string]struct{}{})
	fillBlockedInputEvidenceRequestIDs(turns, nil)
	for _, turn := range turns {
		if turn.BlockedInputEvidenceRequestIDs != nil {
			t.Fatalf("空集合时字段应为 nil：%v", turn.BlockedInputEvidenceRequestIDs)
		}
	}
}

func TestBlockedInputEvidenceFieldIsOmittedWhenEmpty(t *testing.T) {
	body, err := json.Marshal(types.AccessRetentionTurnInfo{RequestIDs: []string{"r1"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "blocked_input_evidence_request_ids") {
		t.Fatalf("字段为空时不应输出：%s", body)
	}
	body, _ = json.Marshal(types.AccessRetentionTurnInfo{BlockedInputEvidenceRequestIDs: []string{"r1"}})
	if !strings.Contains(string(body), `"blocked_input_evidence_request_ids":["r1"]`) {
		t.Fatalf("有值时应输出：%s", body)
	}
}

func TestAttachBlockedInputEvidenceRequestIDsQueriesOnceWithDedupedIDs(t *testing.T) {
	turns := turnsWithRequests([]string{"r1", "r2"}, []string{"r2", "r3"})
	calls := 0
	var asked []string
	var askedTenant string
	attachBlockedInputEvidenceRequestIDs(context.Background(), &repository.User{TenantID: "t1", Role: "platform_admin"}, turns,
		func(_ context.Context, tenantID string, ids []string) (map[string]struct{}, error) {
			calls++
			askedTenant, asked = tenantID, ids
			return map[string]struct{}{"r2": {}}, nil
		})
	if calls != 1 || askedTenant != "t1" || !reflect.DeepEqual(asked, []string{"r1", "r2", "r3"}) {
		t.Fatalf("calls=%d tenant=%q ids=%v", calls, askedTenant, asked)
	}
	if !reflect.DeepEqual(turns[0].BlockedInputEvidenceRequestIDs, []string{"r2"}) || !reflect.DeepEqual(turns[1].BlockedInputEvidenceRequestIDs, []string{"r2"}) {
		t.Fatalf("turns=%+v", turns)
	}
}

func TestAttachBlockedInputEvidenceRequestIDsSkipsQueryForUnauthorizedUsers(t *testing.T) {
	lookup := func(context.Context, string, []string) (map[string]struct{}, error) {
		t.Fatal("无权角色不应查询原文留证")
		return nil, nil
	}
	for _, user := range []*repository.User{
		nil,
		{TenantID: "t1", Role: "viewer"},
		{TenantID: "t1", Role: "platform_admin", DepartmentAssignmentMode: "emergency"},
	} {
		turns := turnsWithRequests([]string{"r1"})
		attachBlockedInputEvidenceRequestIDs(context.Background(), user, turns, lookup)
		if turns[0].BlockedInputEvidenceRequestIDs != nil {
			t.Fatalf("无权角色不应返回字段：%+v", turns[0])
		}
	}
}

func TestAttachBlockedInputEvidenceRequestIDsIgnoresLookupFailure(t *testing.T) {
	turns := turnsWithRequests([]string{"r1"})
	attachBlockedInputEvidenceRequestIDs(context.Background(), &repository.User{TenantID: "t1", Role: "platform_admin"}, turns,
		func(context.Context, string, []string) (map[string]struct{}, error) { return nil, errors.New("boom") })
	if turns[0].BlockedInputEvidenceRequestIDs != nil {
		t.Fatalf("查询失败应当作没有：%+v", turns[0])
	}
}
