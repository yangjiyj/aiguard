package bootstrap

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type stubUserRepo struct {
	user                *repository.User
	updateCalls         int
	updatePasswordCalls int
	lastMustChange      bool
}

func (s *stubUserRepo) GetByID(ctx context.Context, id string) (*repository.User, error) {
	return s.user, nil
}

func (s *stubUserRepo) Update(ctx context.Context, user *repository.User) error {
	s.updateCalls++
	copied := *user
	s.user = &copied
	return nil
}

func (s *stubUserRepo) UpdatePassword(ctx context.Context, userID, passwordHash string, mustChangePassword bool) error {
	s.updatePasswordCalls++
	s.lastMustChange = mustChangePassword
	s.user.PasswordHash = passwordHash
	s.user.MustChangePassword = mustChangePassword
	return nil
}

type stubSystemRepo struct {
	values map[string]string
}

func (s *stubSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if value, ok := s.values[key]; ok {
		return &repository.SystemSetting{Key: key, Value: value}, nil
	}
	return nil, nil
}

func (s *stubSystemRepo) Set(ctx context.Context, key, value string) error {
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	return nil
}

func TestApplyAdminConfigUpdatesBootstrapAdmin(t *testing.T) {
	userRepo := &stubUserRepo{
		user: &repository.User{
			ID:       "user_admin",
			Username: "admin",
			Email:    "admin@local",
			Role:     "platform_admin",
			Status:   "active",
		},
	}
	systemRepo := &stubSystemRepo{values: map[string]string{}}
	cfg := AdminConfig{
		Username: "customer-admin",
		Email:    "customer@example.com",
		Password: "StrongPassw0rd!",
	}

	if err := ApplyAdminConfig(context.Background(), userRepo, systemRepo, cfg); err != nil {
		t.Fatalf("ApplyAdminConfig() error = %v", err)
	}

	if userRepo.user.Username != "customer-admin" {
		t.Fatalf("expected username updated, got %q", userRepo.user.Username)
	}
	if userRepo.user.Email != "customer@example.com" {
		t.Fatalf("expected email updated, got %q", userRepo.user.Email)
	}
	if !userRepo.user.MustChangePassword || !userRepo.lastMustChange {
		t.Fatalf("expected must_change_password=true")
	}
	if userRepo.updateCalls != 1 || userRepo.updatePasswordCalls != 1 {
		t.Fatalf("expected one profile update and one password update, got %d/%d", userRepo.updateCalls, userRepo.updatePasswordCalls)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(userRepo.user.PasswordHash), []byte("StrongPassw0rd!")); err != nil {
		t.Fatalf("expected stored password hash to match configured password: %v", err)
	}
	if got := systemRepo.values[bootstrapFingerprintSetting]; got != cfg.Fingerprint() {
		t.Fatalf("expected fingerprint stored, got %q", got)
	}
}

func TestApplyAdminConfigSkipsWhenFingerprintMatches(t *testing.T) {
	cfg := AdminConfig{
		Username: "admin",
		Email:    "admin@local",
		Password: "StrongPassw0rd!",
	}
	userRepo := &stubUserRepo{
		user: &repository.User{
			ID:       "user_admin",
			Username: "admin",
			Email:    "admin@local",
			Role:     "platform_admin",
			Status:   "active",
		},
	}
	systemRepo := &stubSystemRepo{
		values: map[string]string{
			bootstrapFingerprintSetting: cfg.Fingerprint(),
		},
	}

	if err := ApplyAdminConfig(context.Background(), userRepo, systemRepo, cfg); err != nil {
		t.Fatalf("ApplyAdminConfig() error = %v", err)
	}

	if userRepo.updateCalls != 0 || userRepo.updatePasswordCalls != 0 {
		t.Fatalf("expected no updates when fingerprint matches, got %d/%d", userRepo.updateCalls, userRepo.updatePasswordCalls)
	}
}

func TestApplyAdminConfigSkipsWhenPasswordEmpty(t *testing.T) {
	userRepo := &stubUserRepo{
		user: &repository.User{
			ID:       "user_admin",
			Username: "admin",
			Email:    "admin@local",
			Role:     "platform_admin",
			Status:   "active",
		},
	}
	systemRepo := &stubSystemRepo{}

	err := ApplyAdminConfig(context.Background(), userRepo, systemRepo, AdminConfig{
		Username: "admin",
		Email:    "admin@local",
	})
	if err != nil {
		t.Fatalf("expected nil error when bootstrap password is empty, got %v", err)
	}
	if userRepo.updateCalls != 0 || userRepo.updatePasswordCalls != 0 {
		t.Fatalf("expected no updates when bootstrap password is empty, got %d/%d", userRepo.updateCalls, userRepo.updatePasswordCalls)
	}
}

func TestEnsureLicenseInstallAnchor(t *testing.T) {
	repo := &stubSystemRepo{values: map[string]string{}}
	now := time.Date(2026, 6, 26, 8, 0, 0, 0, time.UTC)
	if err := EnsureLicenseInstallAnchor(context.Background(), repo, now); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.Get(context.Background(), LicenseInstallAnchorKey)
	if got == nil || got.Value != now.Format(time.RFC3339) {
		t.Fatalf("首次应写入 now, got %v", got)
	}
	later := now.Add(48 * time.Hour)
	_ = EnsureLicenseInstallAnchor(context.Background(), repo, later)
	got2, _ := repo.Get(context.Background(), LicenseInstallAnchorKey)
	if got2.Value != now.Format(time.RFC3339) {
		t.Fatalf("已存在不应覆盖")
	}
}
