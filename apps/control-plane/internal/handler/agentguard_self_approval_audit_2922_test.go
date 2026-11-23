package handler

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type selfApprovalChainEvent struct {
	tenantID, eventType, eventID string
	payload                      map[string]any
}

type selfApprovalChainWriter struct{ got chan selfApprovalChainEvent }

func (w *selfApprovalChainWriter) Append(_ context.Context, tenantID, eventType, eventID string, payload map[string]any) error {
	w.got <- selfApprovalChainEvent{tenantID: tenantID, eventType: eventType, eventID: eventID, payload: payload}
	return nil
}

// ws5EnsureUser 建一个真实用户：本人批准的审计经事务审计写 audit_operations.user_id（外键 users）。
func ws5EnsureUser(t *testing.T, pool *pgxpool.Pool, tenantID, userID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id, tenant_id, username) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
		userID, tenantID, fmt.Sprintf("%s-%s", userID, tenantID)); err != nil {
		t.Fatalf("seed user %s: %v", userID, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1 AND tenant_id=$2`, userID, tenantID)
	})
}

// 复审（真库）：本人批准的审计 agentguard_confirmation.self_approved 走仓库现有的事务审计
// （writeTransactionalOperationAudit + commitWithOperationAudit）：与批准同一事务写 audit_operations，
// 提交后进审计链，来源地址取 requestClientIP。单人批准、双人审批的第一次批准各一条，拒绝的本人批准没有。
func TestWS5Confirmation2922SelfApprovalAuditInTransactionDB(t *testing.T) {
	pool, tenantID := ws5ConfirmationDB(t)
	ws5EnsureUser(t, pool, tenantID, "u_requester")
	chain := &selfApprovalChainWriter{got: make(chan selfApprovalChainEvent, 8)}
	sys := &ws5DualApprovalSystemRepo{allowSelf: true}
	deps := &Dependencies{
		AgentGuardPolicyRepo: repository.NewAgentGuardPolicyRepository(pool),
		SystemRepo:           sys,
		ConfirmationReplayer: ws5NoopReplayer{},
		AuditAppender:        audit_chain.NewAppender(chain, false),
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_operations WHERE action_type='agentguard_confirmation.self_approved' AND tenant_id=$1`, tenantID)
	})
	// 审计链里还有确认单处置等其他审计，只看本人批准这一类。
	nextSelfApproval := func(wait time.Duration) (selfApprovalChainEvent, bool) {
		deadline := time.After(wait)
		for {
			select {
			case event := <-chain.got:
				if event.payload["action_type"] == "agentguard_confirmation.self_approved" {
					return event, true
				}
			case <-deadline:
				return selfApprovalChainEvent{}, false
			}
		}
	}
	chained := func(id string) selfApprovalChainEvent {
		t.Helper()
		event, ok := nextSelfApproval(5 * time.Second)
		if !ok {
			t.Fatalf("the self approval of %s never reached the audit chain", id)
		}
		if event.tenantID != tenantID || event.payload["confirmation_id"] != id || event.payload["actor_user_id"] != "u_requester" {
			t.Fatalf("unexpected self approval record: %+v", event)
		}
		if extra, again := nextSelfApproval(300 * time.Millisecond); again {
			t.Fatalf("exactly one self approval record per approval, got another: %+v", extra)
		}
		return event
	}
	stored := func(eventID string) (ip string) {
		t.Helper()
		if err := pool.QueryRow(context.Background(), `SELECT COALESCE(ip_address,'') FROM audit_operations
			WHERE id=$1 AND tenant_id=$2 AND user_id='u_requester' AND action_type='agentguard_confirmation.self_approved'`, eventID, tenantID).Scan(&ip); err != nil {
			t.Fatalf("the chained record must be the audit_operations row written in the transaction: %v", err)
		}
		return ip
	}

	single := ws5CreateConfirmation(t, deps, tenantID, "call_self_tx", `{"url":"https://x.example/self-tx"}`)
	if rec := ws5Resolve(deps, tenantID, single, "u_requester", "approved"); rec.Code != http.StatusOK {
		t.Fatalf("self approval: %d %s", rec.Code, rec.Body.String())
	}
	event := chained(single)
	if event.payload["status"] != "approved" || event.payload["awaiting_second_approval"] != false {
		t.Fatalf("single self approval record: %+v", event.payload)
	}
	if ip := stored(event.eventID); ip != "192.0.2.1" {
		t.Fatalf("source address comes from requestClientIP, got %q", ip)
	}

	sys.dual = true
	dual := ws5CreateConfirmation(t, deps, tenantID, "call_self_dual", `{"url":"https://x.example/self-dual"}`)
	if rec := ws5Resolve(deps, tenantID, dual, "u_requester", "approved"); rec.Code != http.StatusAccepted {
		t.Fatalf("self first approval under dual approval: %d %s", rec.Code, rec.Body.String())
	}
	if event := chained(dual); event.payload["awaiting_second_approval"] != true {
		t.Fatalf("a self first approval is audited too: %+v", event.payload)
	}

	sys.dual, sys.allowSelf = false, false
	refused := ws5CreateConfirmation(t, deps, tenantID, "call_self_refused", `{"url":"https://x.example/self-refused"}`)
	if rec := ws5Resolve(deps, tenantID, refused, "u_requester", "approved"); rec.Code != http.StatusForbidden {
		t.Fatalf("self approval with the switch off: %d %s", rec.Code, rec.Body.String())
	}
	if extra, ok := nextSelfApproval(300 * time.Millisecond); ok {
		t.Fatalf("a refused self approval must not reach the audit chain: %+v", extra)
	}
	for _, op := range sys.operations {
		if op.ActionType == "agentguard_confirmation.self_approved" {
			t.Fatalf("the handler must not write a second, out-of-transaction audit: %+v", op)
		}
	}
}
