package repository

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/jackc/pgx/v5"
)

var (
	ErrAgentIntentAuthorizationUnresolved = errors.New("agent intent authorization is unresolved")
	intentArgumentsHashPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// AgentIntentAuthorizationContext keeps T13 authority results separate from
// the non-authorizing approved-task context used to assess deviations.
type AgentIntentAuthorizationContext struct {
	Resolutions         []agentintent.AuthorizationResolution
	AuthorizationStatus string
	TaskStatus          string
	Task                *AgentIntentTask
}

// ResolveIntentAuthorizationContext uses one transaction for T13 row rechecks
// and task/principal/grant context. A task may be returned when the current
// effect is denied, unsupported, or outside task scope; this is context only
// and never changes per-call authorization.
func (r *AgentAuthorizationRepository) ResolveIntentAuthorizationContext(
	ctx context.Context, tenantID, endpointID string, request agentintent.AuthorizationResolveRequest,
) (AgentIntentAuthorizationContext, error) {
	out := AgentIntentAuthorizationContext{
		Resolutions:         []agentintent.AuthorizationResolution{},
		AuthorizationStatus: "not_requested",
		TaskStatus:          "missing",
	}
	tenantID, endpointID = strings.TrimSpace(tenantID), strings.TrimSpace(endpointID)
	if tenantID == "" || endpointID == "" || len(endpointID) > 128 ||
		(request.Product != "claude-code" && request.Product != "openclaw" && request.Product != "opencode") {
		return out, ErrAgentAuthorizationInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)

	if len(request.Facets) > 0 {
		resolutions, resolveErr := resolveIntentAuthorizationsWithQuerier(ctx, tx, tenantID, endpointID, request)
		switch {
		case resolveErr == nil:
			out.Resolutions = resolutions
			out.AuthorizationStatus = "resolved"
		case errors.Is(resolveErr, ErrAgentAuthorizationInvalid), errors.Is(resolveErr, ErrAgentIntentAuthorizationUnresolved):
			out.AuthorizationStatus = "unresolved"
		default:
			return out, resolveErr
		}
	}
	if request.IntentTaskID != "" {
		out.TaskStatus = "unresolved"
		principalID := ""
		if out.AuthorizationStatus == "resolved" && len(out.Resolutions) > 0 {
			principalID = out.Resolutions[0].PrincipalID
			for _, resolution := range out.Resolutions[1:] {
				if resolution.PrincipalID != principalID {
					principalID = ""
					out.AuthorizationStatus = "unresolved"
					out.Resolutions = []agentintent.AuthorizationResolution{}
					break
				}
			}
		}
		task, taskErr := resolveIntentTaskWithQuerier(ctx, tx, tenantID, endpointID, request.Product,
			request.IntentTaskID, principalID, request.Facets, request.Sources)
		if taskErr == nil {
			out.Task, out.TaskStatus = task, "resolved"
		} else if !errors.Is(taskErr, ErrAgentIntentTaskUnresolved) && !errors.Is(taskErr, ErrAgentIntentTaskInvalid) {
			return out, taskErr
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return AgentIntentAuthorizationContext{}, err
	}
	return out, nil
}

// ResolveIntentAuthorizations re-resolves the exact T14 idempotency tuples
// against persisted T13 decisions. The tenant and endpoint come from the
// endpoint-token middleware; client identity/scope claims are never accepted
// here. This path is read-only and never consumes authorization quota.
func (r *AgentAuthorizationRepository) ResolveIntentAuthorizations(
	ctx context.Context,
	tenantID, endpointID string,
	request agentintent.AuthorizationResolveRequest,
) ([]agentintent.AuthorizationResolution, error) {
	return resolveIntentAuthorizationsWithQuerier(ctx, r.db, tenantID, endpointID, request)
}

type t13AuthorizationQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func resolveIntentAuthorizationsWithQuerier(
	ctx context.Context, querier t13AuthorizationQuerier,
	tenantID, endpointID string, request agentintent.AuthorizationResolveRequest,
) ([]agentintent.AuthorizationResolution, error) {
	tenantID, endpointID = strings.TrimSpace(tenantID), strings.TrimSpace(endpointID)
	if tenantID == "" || endpointID == "" || len(endpointID) > 128 ||
		!validIntentResolveRequest(request) {
		return nil, ErrAgentAuthorizationInvalid
	}

	type expectedFacet = expectedT13Facet
	expected := make([]expectedFacet, 0, len(request.Facets))
	keys := make([]string, 0, len(request.Facets))
	byKey := make(map[string]expectedFacet, len(request.Facets))
	for _, facet := range request.Facets {
		key, err := agentintent.AuthorizationIdempotencyKey(request.Product, endpointID,
			request.SessionID, request.ToolUseID, request.ArgumentsHash, request.ToolName, facet)
		if err != nil {
			return nil, ErrAgentAuthorizationInvalid
		}
		hash, err := agentAuthorizationRequestHash(AgentAuthorizationRequest{
			Action: facet.Action, ResourceType: facet.ResourceType, ResourceID: facet.ResourceID,
			IdempotencyKey: key,
		})
		if err != nil {
			return nil, ErrAgentAuthorizationInvalid
		}
		item := expectedFacet{facet: facet, key: key, hash: hash}
		expected = append(expected, item)
		keys = append(keys, key)
		byKey[key] = item
	}

	rows, err := querier.Query(ctx, `
		SELECT request.idempotency_key, request.principal_id::text, request.request_hash,
		       request.state, request.decision_json, COALESCE(request.grant_id::text,''),
	       request.expires_at > clock_timestamp(),
	       principal.status, principal.revoked_at IS NOT NULL,
	       principal.expires_at > clock_timestamp(),
	       COALESCE(grant_row.id::text,''), COALESCE(grant_row.action,''),
	       COALESCE(grant_row.resource_type,''), COALESCE(grant_row.resource_id,''),
	       COALESCE(grant_row.expires_at > clock_timestamp(),FALSE)
		FROM agent_authorization_requests AS request
		JOIN agent_authorization_principals AS principal
		  ON principal.tenant_id=request.tenant_id AND principal.id=request.principal_id
		LEFT JOIN agent_authorization_grants AS grant_row
		  ON grant_row.tenant_id=request.tenant_id AND grant_row.principal_id=request.principal_id
		 AND grant_row.id=request.grant_id
		WHERE request.tenant_id=$1 AND request.idempotency_key=ANY($2::text[])
		ORDER BY request.idempotency_key, request.principal_id
		FOR SHARE OF request, principal
	`, tenantID, keys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byKeyRows := make(map[string][]resolvedT13AuthorizationRow, len(keys))
	for rows.Next() {
		var row resolvedT13AuthorizationRow
		var revoked, requestActive, principalActive, grantActive bool
		var grantID, grantAction, grantType, grantResource string
		if err := rows.Scan(&row.key, &row.principalID, &row.requestHash, &row.state, &row.decisionJSON,
			&row.requestGrantID, &requestActive, &row.principalStatus, &revoked, &principalActive,
			&grantID, &grantAction, &grantType, &grantResource, &grantActive); err != nil {
			return nil, err
		}
		row.requestActive, row.principalActive, row.grantActive = requestActive, principalActive, grantActive
		row.revoked = revoked
		row.grantID, row.grantAction, row.grantType, row.grantResource = grantID, grantAction, grantType, grantResource
		byKeyRows[row.key] = append(byKeyRows[row.key], row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var resolveNow time.Time
	if err := querier.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&resolveNow); err != nil {
		return nil, err
	}
	resolutions := make([]agentintent.AuthorizationResolution, 0, len(expected))
	principalID := ""
	for _, item := range expected {
		matches := byKeyRows[item.key]
		if len(matches) != 1 {
			return nil, ErrAgentIntentAuthorizationUnresolved
		}
		row := matches[0]
		resolution, err := resolveT13Row(ctx, querier, tenantID, item, row, resolveNow)
		if err != nil {
			return nil, err
		}
		if principalID == "" {
			principalID = row.principalID
		} else if principalID != row.principalID {
			return nil, ErrAgentIntentAuthorizationUnresolved
		}
		resolutions = append(resolutions, resolution)
	}
	return resolutions, nil
}

type expectedT13Facet struct {
	facet agentintent.AuthorizationFacet
	key   string
	hash  string
}

// t13DelegationChainDeniedReason is the existing Authorize reason for a broken ancestry.
const t13DelegationChainDeniedReason = "delegation_parent_inactive"

// isDelegationChainFault separates ancestry/binding faults (fail closed as deny)
// from infrastructure errors (returned, surfaced as 409/unavailable).
func isDelegationChainFault(err error) bool {
	return errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) || errors.Is(err, ErrAgentAuthorizationInvalid)
}

// resolveT13Row recomputes the expected request_hash with the same delegated
// project binding Authorize used (bindDelegatedRequest). Root principals keep
// the unbound hash and their previous result. A delegated principal whose chain
// is broken, cyclic, too deep, cross-project, revoked/expired or unbindable
// resolves as an explicit deny so the T13 block floor still applies.
func resolveT13Row(ctx context.Context, q t13AuthorizationQuerier, tenantID string,
	item expectedT13Facet, row resolvedT13AuthorizationRow, now time.Time) (agentintent.AuthorizationResolution, error) {
	denied := agentintent.AuthorizationResolution{Facet: item.facet, IdempotencyKey: item.key,
		Reason: safeIntentDecisionReason(t13DelegationChainDeniedReason), PrincipalID: row.principalID}
	chain, err := walkAgentDelegationChain(ctx, q, tenantID, row.principalID, now, "")
	if err != nil && !isDelegationChainFault(err) {
		return agentintent.AuthorizationResolution{}, err
	}
	if err != nil {
		return denied, nil
	}
	request := AgentAuthorizationRequest{Action: item.facet.Action, ResourceType: item.facet.ResourceType,
		ResourceID: item.facet.ResourceID, IdempotencyKey: item.key}
	if len(chain) > 0 {
		if err := bindDelegatedRequest(chain, &request); err != nil {
			if !isDelegationChainFault(err) {
				return agentintent.AuthorizationResolution{}, err
			}
			return denied, nil
		}
		if item.hash, err = agentAuthorizationRequestHash(request); err != nil {
			return agentintent.AuthorizationResolution{}, err
		}
	}
	decision, err := verifyResolvedT13Authorization(item, row)
	if err != nil {
		return agentintent.AuthorizationResolution{}, err
	}
	if decision.Allowed {
		var lockedGrantID string
		err = q.QueryRow(ctx, `SELECT id::text FROM agent_authorization_grants
			WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND action=$4 AND resource_type=$5
			AND resource_id=$6 AND expires_at>clock_timestamp() FOR SHARE`, tenantID, row.principalID, row.requestGrantID,
			item.facet.Action, item.facet.ResourceType, item.facet.ResourceID).Scan(&lockedGrantID)
		if err != nil || lockedGrantID != row.requestGrantID {
			return agentintent.AuthorizationResolution{}, ErrAgentIntentAuthorizationUnresolved
		}
		if len(chain) > 0 {
			// A stored delegated allow is only current while every mapped ancestor grant still covers it.
			_, err = walkAncestorGrantLimits(ctx, q, tenantID, chain, row.requestGrantID, request.Action,
				request.ResourceType, request.ResourceID, request.Context, now, "")
			if err != nil && !isDelegationChainFault(err) {
				return agentintent.AuthorizationResolution{}, err
			}
			if err != nil {
				return denied, nil
			}
		}
	}
	return agentintent.AuthorizationResolution{
		Facet: item.facet, IdempotencyKey: item.key, Allowed: decision.Allowed,
		Reason: safeIntentDecisionReason(decision.Reason), PrincipalID: row.principalID,
		GrantID: row.requestGrantID,
	}, nil
}

type resolvedT13AuthorizationRow struct {
	key, principalID, requestHash, state, requestGrantID            string
	decisionJSON                                                    []byte
	requestActive, principalActive, grantActive, revoked            bool
	principalStatus, grantID, grantAction, grantType, grantResource string
}

func validIntentResolveRequest(request agentintent.AuthorizationResolveRequest) bool {
	if request.Product != "claude-code" && request.Product != "openclaw" && request.Product != "opencode" {
		return false
	}
	if request.SessionID == "" || len(request.SessionID) > 128 || request.ToolUseID == "" ||
		len(request.ToolUseID) > 128 || request.ToolName == "" || len(request.ToolName) > 255 ||
		!intentArgumentsHashPattern.MatchString(request.ArgumentsHash) || len(request.Facets) == 0 || len(request.Facets) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(request.Facets))
	for _, facet := range request.Facets {
		if !validAgentAuthorizationLabel(facet.Action) || !validAgentAuthorizationLabel(facet.ResourceType) ||
			!validAgentAuthorizationResourceID(facet.ResourceID) {
			return false
		}
		key := facet.Action + "\x00" + facet.ResourceType + "\x00" + facet.ResourceID
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func verifyResolvedT13Authorization(expected struct {
	facet agentintent.AuthorizationFacet
	key   string
	hash  string
}, row resolvedT13AuthorizationRow) (*AgentAuthorizationDecision, error) {
	if row.key != expected.key || row.requestHash != expected.hash || row.state != "complete" ||
		!row.requestActive || row.principalStatus != "active" || row.revoked || !row.principalActive ||
		row.principalID == "" || len(row.decisionJSON) == 0 {
		return nil, ErrAgentIntentAuthorizationUnresolved
	}
	var decision AgentAuthorizationDecision
	if err := json.Unmarshal(row.decisionJSON, &decision); err != nil {
		return nil, ErrAgentIntentAuthorizationUnresolved
	}
	if decision.PrincipalID != row.principalID || decision.IdempotencyKey != expected.key ||
		decision.Action != expected.facet.Action || decision.ResourceType != expected.facet.ResourceType ||
		decision.ResourceID != expected.facet.ResourceID {
		return nil, ErrAgentIntentAuthorizationUnresolved
	}
	if decision.Allowed {
		if row.requestGrantID == "" || decision.GrantID != row.requestGrantID || row.grantID != row.requestGrantID ||
			row.grantAction != expected.facet.Action || row.grantType != expected.facet.ResourceType ||
			row.grantResource != expected.facet.ResourceID || !row.grantActive {
			return nil, ErrAgentIntentAuthorizationUnresolved
		}
	} else if row.requestGrantID != "" || decision.GrantID != "" {
		return nil, ErrAgentIntentAuthorizationUnresolved
	}
	return &decision, nil
}

func safeIntentDecisionReason(reason string) string {
	switch reason {
	case "allowed", "no_matching_grant", "quota_exceeded", "grant_expired", "condition_mismatch", t13DelegationChainDeniedReason:
		return reason
	default:
		return "decision_unclassified"
	}
}
