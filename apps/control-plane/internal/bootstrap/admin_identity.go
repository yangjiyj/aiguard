package bootstrap

import (
	"context"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
)

const bootstrapAdminTenantID = "tenant_default"

type AdminLoginIdentityClient interface {
	CreateUser(context.Context, localidentity.CreateUserInput) (string, error)
	SetEnabled(context.Context, string, bool) error
	ResetPassword(context.Context, string, string, bool) error
	DeleteUser(context.Context, string) error
}

type AdminLoginIdentityStore interface {
	FindSubjectByUser(context.Context, string, string) (string, error)
	BindLoginSources(context.Context, string, string, string, string) error
}

// EnsureAdminLoginIdentity makes the installer bootstrap administrator usable
// in the employee Chat portal with the same username and password. It is a
// no-op when the bundled identity runtime is not configured, and idempotently
// refreshes password, enabled state and issuer links when it is configured.
func EnsureAdminLoginIdentity(
	ctx context.Context,
	client AdminLoginIdentityClient,
	store AdminLoginIdentityStore,
	issuer string,
	cfg AdminConfig,
) error {
	if client == nil || store == nil {
		return nil
	}
	cfg = cfg.normalized()
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	if cfg.Username == "" || cfg.Password == "" || issuer == "" {
		return nil
	}

	subject, err := store.FindSubjectByUser(ctx, bootstrapAdminTenantID, bootstrapAdminID)
	created := false
	if err != nil {
		return err
	}
	if strings.TrimSpace(subject) == "" {
		subject, err = client.CreateUser(ctx, localidentity.CreateUserInput{
			Username:  cfg.Username,
			Email:     cfg.Email,
			Password:  cfg.Password,
			Temporary: false,
		})
		if err != nil {
			return err
		}
		created = true
	}

	if err := store.BindLoginSources(ctx, bootstrapAdminTenantID, bootstrapAdminID, issuer, subject); err != nil {
		if created {
			_ = client.DeleteUser(context.WithoutCancel(ctx), subject)
		}
		return err
	}
	if err := client.SetEnabled(ctx, subject, true); err != nil {
		return err
	}
	return nil
}

// EnsureAdminLoginIdentityUntilReady retries while the bundled identity runtime
// is starting. It never blocks control-plane health and stops after success or
// context cancellation.
func EnsureAdminLoginIdentityUntilReady(
	ctx context.Context,
	interval time.Duration,
	ensure func(context.Context) error,
	onError func(error),
	onReady func(),
) {
	if ensure == nil {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		if err := ensure(ctx); err == nil {
			if onReady != nil {
				onReady()
			}
			return
		} else if onError != nil {
			onError(err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}
