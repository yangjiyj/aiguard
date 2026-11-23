package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	bootstrapAdminID            = "user_admin"
	bootstrapFingerprintSetting = "bootstrap_admin_config_fingerprint"
)

type UserRepo interface {
	GetByID(ctx context.Context, id string) (*repository.User, error)
	Update(ctx context.Context, user *repository.User) error
	UpdatePassword(ctx context.Context, userID, passwordHash string, mustChangePassword bool) error
}

type SystemRepo interface {
	Get(ctx context.Context, key string) (*repository.SystemSetting, error)
	Set(ctx context.Context, key, value string) error
}

// SessionRevoker 吊销某用户的全部会话（由 repository.SessionRepository 满足）。
type SessionRevoker interface {
	DeleteByUser(ctx context.Context, userID string) error
}

type AdminConfig struct {
	Username string
	Email    string
	Password string
	// Sessions 可选：引导管理员的角色被改写时吊销其全部会话（M-1）。不参与指纹。
	Sessions SessionRevoker
}

func (c AdminConfig) normalized() AdminConfig {
	return AdminConfig{
		Username: strings.TrimSpace(c.Username),
		Email:    strings.TrimSpace(c.Email),
		Password: c.Password,
		Sessions: c.Sessions,
	}
}

func (c AdminConfig) Fingerprint() string {
	sum := sha256.Sum256([]byte(c.Username + "\n" + c.Email + "\n" + c.Password))
	return hex.EncodeToString(sum[:])
}

func ApplyAdminConfig(ctx context.Context, userRepo UserRepo, systemRepo SystemRepo, cfg AdminConfig) error {
	cfg = cfg.normalized()
	if cfg.Password == "" {
		return nil
	}

	fingerprint := cfg.Fingerprint()
	current, err := systemRepo.Get(ctx, bootstrapFingerprintSetting)
	if err != nil {
		return fmt.Errorf("load bootstrap fingerprint: %w", err)
	}
	if current != nil && current.Value == fingerprint {
		return nil
	}

	user, err := userRepo.GetByID(ctx, bootstrapAdminID)
	if err != nil {
		return fmt.Errorf("load bootstrap admin: %w", err)
	}
	if user == nil {
		return fmt.Errorf("bootstrap admin user %q not found", bootstrapAdminID)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash bootstrap admin password: %w", err)
	}

	roleChanged := user.Role != "platform_admin"
	user.Username = cfg.Username
	user.Email = cfg.Email
	user.Role = "platform_admin"
	user.Status = "active"
	user.MustChangePassword = true

	if err := userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("update bootstrap admin profile: %w", err)
	}
	if err := userRepo.UpdatePassword(ctx, user.ID, string(hashedPassword), true); err != nil {
		return fmt.Errorf("update bootstrap admin password: %w", err)
	}
	// M-1：角色被改写（例如原先是 auditor）时，旧会话不得继续带着新角色的权限。吊销失败则整体失败（fail-closed），
	// 不落指纹，下次启动会重试。
	if roleChanged && cfg.Sessions != nil {
		if err := cfg.Sessions.DeleteByUser(ctx, user.ID); err != nil {
			return fmt.Errorf("revoke bootstrap admin sessions after role change: %w", err)
		}
	}
	if err := systemRepo.Set(ctx, bootstrapFingerprintSetting, fingerprint); err != nil {
		return fmt.Errorf("persist bootstrap fingerprint: %w", err)
	}

	return nil
}

// LicenseInstallAnchorKey 记录平台首次启动时间，用于零签名试用窗口判定。
const LicenseInstallAnchorKey = "enterprise_license_install_anchor"

// EnsureLicenseInstallAnchor 首次启动写入安装时间锚点（幂等），用于零签名试用判定。
func EnsureLicenseInstallAnchor(ctx context.Context, repo SystemRepo, now time.Time) error {
	existing, err := repo.Get(ctx, LicenseInstallAnchorKey)
	if err != nil {
		return err
	}
	if existing != nil && existing.Value != "" {
		return nil
	}
	return repo.Set(ctx, LicenseInstallAnchorKey, now.UTC().Format(time.RFC3339))
}
