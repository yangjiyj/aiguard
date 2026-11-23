package bootstrap

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type recordingSessions struct{ deleted []string }

func (r *recordingSessions) DeleteByUser(_ context.Context, id string) error {
	r.deleted = append(r.deleted, id)
	return nil
}

// M-1：启动时的管理员配置会把引导管理员强制写成 platform_admin。若它此前是别的角色，旧会话不得继续带着新角色的权限。
func TestApplyAdminConfigRevokesSessionsWhenTheRoleActuallyChanges(t *testing.T) {
	for _, from := range []string{"auditor", "security_officer", "tenant_admin", "viewer"} {
		t.Run(from, func(t *testing.T) {
			repo := &stubUserRepo{user: &repository.User{ID: "user_admin", Username: "admin", Email: "a@x", Role: from, Status: "active"}}
			sessions := &recordingSessions{}
			err := ApplyAdminConfig(context.Background(), repo, &stubSystemRepo{values: map[string]string{}},
				AdminConfig{Username: "boss", Email: "boss@example.com", Password: "StrongPassw0rd!", Sessions: sessions})
			if err != nil {
				t.Fatal(err)
			}
			if len(sessions.deleted) != 1 || sessions.deleted[0] != "user_admin" {
				t.Fatalf("角色 %s → platform_admin 必须吊销该用户的全部会话: %v", from, sessions.deleted)
			}
		})
	}
}

func TestApplyAdminConfigKeepsSessionsWhenTheRoleDoesNotChange(t *testing.T) {
	repo := &stubUserRepo{user: &repository.User{ID: "user_admin", Username: "admin", Email: "a@x", Role: "platform_admin", Status: "active"}}
	sessions := &recordingSessions{}
	if err := ApplyAdminConfig(context.Background(), repo, &stubSystemRepo{values: map[string]string{}},
		AdminConfig{Username: "boss", Email: "boss@example.com", Password: "StrongPassw0rd!", Sessions: sessions}); err != nil {
		t.Fatal(err)
	}
	if len(sessions.deleted) != 0 {
		t.Fatalf("角色没变不应吊销会话: %v", sessions.deleted)
	}
}
