package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrPolicyCenterBehaviorConflict = errors.New("policy center behavior version conflict")

type PolicyCenterExpectedState struct {
	ExpectedVersion string
	ExpectedAbsent  bool
}

type PolicyCenterAgentGuardChange struct {
	ID                      string
	Expected                PolicyCenterExpectedState
	ExpectedPoliciesVersion string
	Policy                  *AgentGuardPolicy
}

type PolicyCenterMCPChange struct {
	ID                      string
	Expected                PolicyCenterExpectedState
	ExpectedPoliciesVersion string
	Policy                  *MCPPolicy
}

type PolicyCenterOperationChange struct {
	ScopeType              string
	ScopeRef               string
	Expected               PolicyCenterExpectedState
	ExpectedStorageVersion int64
	Mutation               *AgentOperationPolicyMutation
}

// nil 候选仅校验对象，允许只写一方时仍以双方的编辑快照作前置条件。
type PolicyCenterAgentBehaviorMutation struct {
	TenantID   string
	ActorID    string
	AgentGuard *PolicyCenterAgentGuardChange
	MCP        *PolicyCenterMCPChange
	Operation  *PolicyCenterOperationChange
}

type PolicyCenterAgentBehaviorRepository struct{ db *pgxpool.Pool }

func NewPolicyCenterAgentBehaviorRepository(db *pgxpool.Pool) *PolicyCenterAgentBehaviorRepository {
	return &PolicyCenterAgentBehaviorRepository{db: db}
}

func PolicyCenterSnapshotVersion(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func PolicyCenterAgentGuardPoliciesVersion(policies []*AgentGuardPolicy) string {
	ordered := []*AgentGuardPolicy{}
	for _, policy := range policies {
		if policy != nil {
			ordered = append(ordered, policy)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return PolicyCenterSnapshotVersion(ordered)
}

func PolicyCenterMCPPoliciesVersion(policies []*MCPPolicy) string {
	ordered := []*MCPPolicy{}
	for _, policy := range policies {
		if policy != nil {
			ordered = append(ordered, policy)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return PolicyCenterSnapshotVersion(ordered)
}

func (expected PolicyCenterExpectedState) matches(exists bool, current any) bool {
	if expected.ExpectedAbsent {
		return expected.ExpectedVersion == "" && !exists
	}
	return expected.ExpectedVersion != "" && exists && expected.ExpectedVersion == PolicyCenterSnapshotVersion(current)
}

func policyCenterBehaviorTransactionError(err error) error {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "40001", "40P01", "23505":
			return fmt.Errorf("%w: %s", ErrPolicyCenterBehaviorConflict, databaseError.Code)
		}
	}
	return err
}

func (r *PolicyCenterAgentBehaviorRepository) Save(ctx context.Context, mutation PolicyCenterAgentBehaviorMutation) (err error) {
	defer func() { err = policyCenterBehaviorTransactionError(err) }()
	mutation.TenantID = strings.TrimSpace(mutation.TenantID)
	if mutation.TenantID == "" || mutation.ActorID == "" {
		return errors.New("tenant_id and actor_id are required")
	}
	if mutation.AgentGuard == nil && mutation.MCP == nil && mutation.Operation == nil {
		return errors.New("behavior mutation is empty")
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin behavior transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	// 固定锁顺序；串行化谓词读取也保护缺失对象与候选集合的并发插入。
	if mutation.AgentGuard != nil {
		if err := checkPolicyCenterAgentGuardTx(ctx, tx, mutation.TenantID, mutation.AgentGuard); err != nil {
			return err
		}
	}
	if mutation.MCP != nil {
		if err := checkPolicyCenterMCPTx(ctx, tx, mutation.TenantID, mutation.MCP); err != nil {
			return err
		}
	}
	if mutation.Operation != nil {
		if err := checkPolicyCenterOperationTx(ctx, tx, mutation.TenantID, mutation.Operation); err != nil {
			return err
		}
	}
	// 所有前置条件在任何写入前检查；配置、版本与审计均属于同一事务。
	if change := mutation.AgentGuard; change != nil && change.Policy != nil {
		candidate := *change.Policy
		if candidate.ID != change.ID || candidate.TenantID != mutation.TenantID {
			return errors.New("agentguard candidate identity mismatch")
		}
		candidate.UpdatedBy = mutation.ActorID
		encoded, err := prepareAgentGuardPolicyForWrite(&candidate, change.Expected.ExpectedAbsent)
		if err != nil {
			return err
		}
		if candidate.ID != change.ID {
			return errors.New("agentguard create requires a managed identity")
		}
		if change.Expected.ExpectedAbsent {
			if err := createAgentGuardPolicyTx(ctx, tx, &candidate, encoded); err != nil {
				return err
			}
		} else {
			updated, err := updateAgentGuardPolicyTx(ctx, tx, &candidate, encoded)
			if err != nil {
				return err
			}
			if !updated {
				return ErrPolicyCenterBehaviorConflict
			}
		}
		stored, err := getAgentGuardPolicyTx(ctx, tx, mutation.TenantID, candidate.ID)
		if err != nil {
			return err
		}
		if stored == nil {
			return ErrPolicyCenterBehaviorConflict
		}
		if _, err := upsertAgentGuardPolicyVersionTx(ctx, tx, stored, mutation.ActorID); err != nil {
			return err
		}
	}
	if change := mutation.MCP; change != nil && change.Policy != nil {
		candidate := *change.Policy
		if candidate.ID != change.ID || candidate.TenantID != mutation.TenantID {
			return errors.New("mcp candidate identity mismatch")
		}
		if change.Expected.ExpectedAbsent {
			if err := createMCPPolicy(ctx, tx, &candidate); err != nil {
				return err
			}
		} else if err := updateMCPPolicy(ctx, tx, &candidate); err != nil {
			return err
		}
	}
	if change := mutation.Operation; change != nil && change.Mutation != nil {
		candidate := *change.Mutation
		if candidate.TenantID != mutation.TenantID || candidate.ScopeType != change.ScopeType || candidate.ScopeRef != change.ScopeRef {
			return errors.New("operation candidate identity mismatch")
		}
		candidate.ActorID = mutation.ActorID
		if change.Expected.ExpectedAbsent {
			candidate.ExpectedVersion = 1
		} else {
			candidate.ExpectedVersion = change.ExpectedStorageVersion
		}
		if _, err := saveAgentOperationPolicyTx(ctx, tx, candidate); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit behavior transaction: %w", err)
	}
	return nil
}

func checkPolicyCenterAgentGuardTx(ctx context.Context, tx pgx.Tx, tenantID string, change *PolicyCenterAgentGuardChange) error {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
		       priority, enabled, COALESCE(template_id, ''), rules_json, behavior_json, dlp_json,
		       COALESCE(created_by, ''), COALESCE(updated_by, ''), created_at, updated_at
		FROM agentguard_policies WHERE tenant_id=$1 ORDER BY id FOR UPDATE
	`, tenantID)
	if err != nil {
		return fmt.Errorf("lock behavior agentguard policies: %w", err)
	}
	policies, err := scanAgentGuardPolicyRows(rows)
	rows.Close()
	if err != nil {
		return err
	}
	if change.ExpectedPoliciesVersion == "" || change.ExpectedPoliciesVersion != PolicyCenterAgentGuardPoliciesVersion(policies) {
		return ErrPolicyCenterBehaviorConflict
	}
	var current *AgentGuardPolicy
	for _, policy := range policies {
		if policy.ID == change.ID {
			current = policy
			break
		}
	}
	if !change.Expected.matches(current != nil, current) {
		return ErrPolicyCenterBehaviorConflict
	}
	return nil
}

func checkPolicyCenterMCPTx(ctx context.Context, tx pgx.Tx, tenantID string, change *PolicyCenterMCPChange) error {
	rows, err := tx.Query(ctx, `SELECT `+mcpPolicyColumns+` FROM mcp_policies WHERE tenant_id=$1 ORDER BY id FOR UPDATE`, tenantID)
	if err != nil {
		return fmt.Errorf("lock behavior mcp policies: %w", err)
	}
	var policies []*MCPPolicy
	for rows.Next() {
		policy, err := scanMCPPolicy(rows)
		if err != nil {
			rows.Close()
			return err
		}
		policies = append(policies, policy)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if change.ExpectedPoliciesVersion == "" || change.ExpectedPoliciesVersion != PolicyCenterMCPPoliciesVersion(policies) {
		return ErrPolicyCenterBehaviorConflict
	}
	var current *MCPPolicy
	for _, policy := range policies {
		if policy.ID == change.ID {
			current = policy
			break
		}
	}
	if !change.Expected.matches(current != nil, current) {
		return ErrPolicyCenterBehaviorConflict
	}
	return nil
}

func checkPolicyCenterOperationTx(ctx context.Context, tx pgx.Tx, tenantID string, change *PolicyCenterOperationChange) error {
	var current AgentOperationPolicy
	var paths, channels, restricted, scopes []byte
	err := tx.QueryRow(ctx, `
		SELECT scope_type, scope_ref, mode, action, protocol, discardable_paths_json,
		       notify_channel_ids_json, restricted_file_patterns_json, restricted_file_action,
		       restricted_file_scopes_json, version, updated_by, updated_at
		FROM agent_destructive_policies
		WHERE tenant_id=$1 AND scope_type=$2 AND scope_ref=$3 AND enabled=true FOR UPDATE
	`, tenantID, change.ScopeType, change.ScopeRef).Scan(
		&current.ScopeType, &current.ScopeRef, &current.Mode, &current.Action, &current.Protocol,
		&paths, &channels, &restricted, &current.RestrictedFileAction, &scopes,
		&current.Version, &current.UpdatedBy, &current.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if change.Expected.matches(false, nil) && change.ExpectedStorageVersion == 0 {
			return nil
		}
		return ErrPolicyCenterBehaviorConflict
	}
	if err != nil {
		return fmt.Errorf("lock behavior operation policy: %w", err)
	}
	if err := json.Unmarshal(paths, &current.DiscardablePaths); err != nil {
		return err
	}
	if err := json.Unmarshal(channels, &current.NotifyChannelIDs); err != nil {
		return err
	}
	if err := json.Unmarshal(restricted, &current.RestrictedFilePatterns); err != nil {
		return err
	}
	current.RestrictedFileScopes = decodeRestrictedFileScopes(scopes)
	current.decorate()
	if current.Version != change.ExpectedStorageVersion || !change.Expected.matches(true, &current) {
		return ErrPolicyCenterBehaviorConflict
	}
	return nil
}
