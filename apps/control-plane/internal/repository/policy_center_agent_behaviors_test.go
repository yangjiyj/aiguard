package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPolicyCenterExpectedStateIsExplicit(t *testing.T) {
	policy := &AgentOperationPolicy{Version: 1}
	version := PolicyCenterSnapshotVersion(policy)
	for _, test := range []struct {
		name     string
		expected PolicyCenterExpectedState
		exists   bool
		want     bool
	}{
		{"absent", PolicyCenterExpectedState{ExpectedAbsent: true}, false, true},
		{"absent_not_v1", PolicyCenterExpectedState{ExpectedAbsent: true}, true, false},
		{"v1", PolicyCenterExpectedState{ExpectedVersion: version}, true, true},
		{"v1_not_absent", PolicyCenterExpectedState{ExpectedVersion: version}, false, false},
		{"no_condition", PolicyCenterExpectedState{}, true, false},
		{"both_conditions", PolicyCenterExpectedState{ExpectedAbsent: true, ExpectedVersion: version}, false, false},
		{"stale", PolicyCenterExpectedState{ExpectedVersion: "stale"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.expected.matches(test.exists, policy); got != test.want {
				t.Fatalf("matches=%v want=%v", got, test.want)
			}
		})
	}
}

func TestPolicyCenterCandidateSetVersionsAreStableAndBindChanges(t *testing.T) {
	first := &AgentGuardPolicy{ID: "a", UpdatedAt: time.Unix(1, 0)}
	second := &AgentGuardPolicy{ID: "b"}
	version := PolicyCenterAgentGuardPoliciesVersion([]*AgentGuardPolicy{first, second})
	if version == "" || version != PolicyCenterAgentGuardPoliciesVersion([]*AgentGuardPolicy{second, first}) {
		t.Fatal("guard set version depended on list order")
	}
	first.UpdatedAt = first.UpdatedAt.Add(time.Second)
	if version == PolicyCenterAgentGuardPoliciesVersion([]*AgentGuardPolicy{first, second}) {
		t.Fatal("guard version ignored storage update")
	}
	if PolicyCenterAgentGuardPoliciesVersion(nil) != PolicyCenterAgentGuardPoliciesVersion([]*AgentGuardPolicy{}) {
		t.Fatal("empty guard set version depended on nil slice")
	}
	mcpFirst, mcpSecond := &MCPPolicy{ID: "a"}, &MCPPolicy{ID: "b"}
	version = PolicyCenterMCPPoliciesVersion([]*MCPPolicy{mcpFirst, mcpSecond})
	if version != PolicyCenterMCPPoliciesVersion([]*MCPPolicy{mcpSecond, mcpFirst}) {
		t.Fatal("mcp set version depended on list order")
	}
	mcpFirst.Note = "concurrent"
	if version == PolicyCenterMCPPoliciesVersion([]*MCPPolicy{mcpFirst, mcpSecond}) {
		t.Fatal("mcp version ignored changed object")
	}
}

func TestPolicyCenterDatabaseConflictsMapToCASConflict(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23505"} {
		if err := policyCenterBehaviorTransactionError(&pgconn.PgError{Code: code}); !errors.Is(err, ErrPolicyCenterBehaviorConflict) {
			t.Fatalf("code %s did not return conflict: %v", code, err)
		}
	}
	failure := &pgconn.PgError{Code: "P0001"}
	if err := policyCenterBehaviorTransactionError(failure); err != failure {
		t.Fatalf("storage failure hidden as conflict: %v", err)
	}
}
