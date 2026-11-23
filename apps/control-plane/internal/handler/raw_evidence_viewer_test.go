package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestCanViewRawEvidenceUser(t *testing.T) {
	cases := []struct {
		name string
		user *repository.User
		want bool
	}{
		{"系统管理员", &repository.User{Role: "platform_admin"}, true},
		{"安全保密员", &repository.User{Role: "security_officer"}, true},
		{"审计员", &repository.User{Role: "auditor"}, false},
		{"租户管理员", &repository.User{Role: "tenant_admin"}, false},
		{"租户所有者", &repository.User{Role: "tenant_owner"}, false},
		{"部门应急指派的系统管理员", &repository.User{Role: "platform_admin", DepartmentAssignmentMode: "emergency"}, false},
		{"部门应急指派的安全保密员", &repository.User{Role: "security_officer", DepartmentAssignmentMode: "emergency"}, false},
		{"空用户", nil, false},
	}
	for _, c := range cases {
		if got := canViewRawEvidenceUser(c.user); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
