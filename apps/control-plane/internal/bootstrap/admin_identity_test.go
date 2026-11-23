package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
)

type adminLoginClientStub struct {
	events         []string
	created        localidentity.CreateUserInput
	createSubject  string
	createErr      error
	resetSubject   string
	resetPassword  string
	resetTemporary bool
	resetErr       error
	enabledSubject string
	enabled        bool
	enableErr      error
	deletedSubject string
}

func (s *adminLoginClientStub) CreateUser(_ context.Context, in localidentity.CreateUserInput) (string, error) {
	s.events = append(s.events, "create")
	s.created = in
	return s.createSubject, s.createErr
}
func (s *adminLoginClientStub) SetEnabled(_ context.Context, subject string, enabled bool) error {
	s.events = append(s.events, "enable")
	s.enabledSubject, s.enabled = subject, enabled
	return s.enableErr
}
func (s *adminLoginClientStub) ResetPassword(_ context.Context, subject, password string, temporary bool) error {
	s.events = append(s.events, "reset")
	s.resetSubject, s.resetPassword, s.resetTemporary = subject, password, temporary
	return s.resetErr
}
func (s *adminLoginClientStub) DeleteUser(_ context.Context, subject string) error {
	s.events = append(s.events, "delete")
	s.deletedSubject = subject
	return nil
}

type adminLoginStoreStub struct {
	subject string
	findErr error
	bound   []string
	bindErr error
}

func (s *adminLoginStoreStub) FindSubjectByUser(context.Context, string, string) (string, error) {
	return s.subject, s.findErr
}
func (s *adminLoginStoreStub) BindLoginSources(_ context.Context, tenantID, userID, issuer, subject string) error {
	s.bound = []string{tenantID, userID, issuer, subject}
	return s.bindErr
}

func TestEnsureAdminLoginIdentityCreatesAndBindsBootstrapAdmin(t *testing.T) {
	client := &adminLoginClientStub{createSubject: "kc-admin"}
	store := &adminLoginStoreStub{}
	cfg := AdminConfig{Username: "admin", Email: "admin@example.test", Password: "secret"}
	if err := EnsureAdminLoginIdentity(context.Background(), client, store, "https://sso.example/sso/realms/jjdguard/", cfg); err != nil {
		t.Fatal(err)
	}
	if client.created.Username != cfg.Username || client.created.Password != cfg.Password || client.created.Temporary {
		t.Fatalf("create input = %+v", client.created)
	}
	wantBound := []string{"tenant_default", "user_admin", "https://sso.example/sso/realms/jjdguard", "kc-admin"}
	if !reflect.DeepEqual(store.bound, wantBound) || !client.enabled || client.enabledSubject != "kc-admin" {
		t.Fatalf("bound=%v enabled=%v subject=%q", store.bound, client.enabled, client.enabledSubject)
	}
	if !reflect.DeepEqual(client.events, []string{"create", "enable"}) {
		t.Fatalf("events=%v", client.events)
	}
}

func TestEnsureAdminLoginIdentityPreservesExistingCredential(t *testing.T) {
	client := &adminLoginClientStub{}
	store := &adminLoginStoreStub{subject: "kc-admin"}
	if err := EnsureAdminLoginIdentity(context.Background(), client, store, "https://sso.example/sso/realms/jjdguard", AdminConfig{Username: "admin", Password: "rotated"}); err != nil {
		t.Fatal(err)
	}
	if client.resetSubject != "" || client.resetPassword != "" {
		t.Fatalf("existing credential was unexpectedly reset")
	}
	if !reflect.DeepEqual(client.events, []string{"enable"}) {
		t.Fatalf("events=%v", client.events)
	}
}

func TestEnsureAdminLoginIdentityCompensatesFailedBinding(t *testing.T) {
	client := &adminLoginClientStub{createSubject: "kc-admin"}
	store := &adminLoginStoreStub{bindErr: errors.New("bind failed")}
	if err := EnsureAdminLoginIdentity(context.Background(), client, store, "https://sso.example/sso/realms/jjdguard", AdminConfig{Username: "admin", Password: "secret"}); err == nil {
		t.Fatal("expected binding error")
	}
	if client.deletedSubject != "kc-admin" || !reflect.DeepEqual(client.events, []string{"create", "delete"}) {
		t.Fatalf("events=%v deleted=%q", client.events, client.deletedSubject)
	}
}

func TestEnsureAdminLoginIdentityIsNoOpWithoutChatRuntime(t *testing.T) {
	if err := EnsureAdminLoginIdentity(context.Background(), nil, nil, "", AdminConfig{Username: "admin", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAdminLoginIdentityUntilReadyRetriesThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	var errorsSeen atomic.Int32
	ready := make(chan struct{}, 1)
	EnsureAdminLoginIdentityUntilReady(
		context.Background(),
		time.Millisecond,
		func(context.Context) error {
			if attempts.Add(1) < 3 {
				return errors.New("not ready")
			}
			return nil
		},
		func(error) { errorsSeen.Add(1) },
		func() { ready <- struct{}{} },
	)
	if attempts.Load() != 3 || errorsSeen.Load() != 2 {
		t.Fatalf("attempts=%d errors=%d", attempts.Load(), errorsSeen.Load())
	}
	select {
	case <-ready:
	default:
		t.Fatal("ready callback not called")
	}
}

func TestEnsureAdminLoginIdentityUntilReadyStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		EnsureAdminLoginIdentityUntilReady(
			ctx,
			time.Hour,
			func(context.Context) error {
				attempts.Add(1)
				cancel()
				return errors.New("not ready")
			},
			nil,
			nil,
		)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retry loop ignored cancellation")
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts=%d", attempts.Load())
	}
}
