// Package mcpadmission 定义 MCP 服务、工具的准入处置来源：控制面按准入记录的 admission_reviewed_by
// 折算来源随解析结果下发，网关据此区分“管理员手动隔离、撤销”（照拦）和“系统自动隔离”（按 mcp.*
// 防护项处置）。不按隔离原因的文字判断：管理员填什么原因都算管理员处置。
package mcpadmission

import "strings"

const (
	// SourceSystem 是系统自动处置（同步、触发器写 admission_reviewed_by='system'）。
	SourceSystem = "system"
	// SourceAdministrator 是管理员手动处置（admission_reviewed_by 为管理员 ID）。
	SourceAdministrator = "administrator"
)

// Source 由 admission_reviewed_by 折算来源：'system' 为系统，其余（含空）为管理员。
func Source(reviewedBy string) string {
	if strings.TrimSpace(reviewedBy) == SourceSystem {
		return SourceSystem
	}
	return SourceAdministrator
}

// AdministratorBlock 判断这个准入状态是不是管理员处置（照拦）：撤销一律算；隔离只要来源不是系统就算
// （旧控制面不下发来源时为空，按管理员处理，不比 2.9.21 宽）。
func AdministratorBlock(status, source string) bool {
	switch status {
	case "revoked":
		return true
	case "quarantined":
		return source != SourceSystem
	}
	return false
}

// ContractSample 是控制面与网关共用的固定样例：两端各自的契约测试都遍历它。
type ContractSample struct {
	Name              string
	Status            string
	ReviewedBy        string
	Reason            string
	WantAdministrator bool
}

// ContractSamples：管理员隔离时原因写成系统发现的文字也照拦；系统隔离按防护项处置。
var ContractSamples = []ContractSample{
	{Name: "管理员隔离、原因填 route_binding_changed", Status: "quarantined", ReviewedBy: "user_admin", Reason: "route_binding_changed", WantAdministrator: true},
	{Name: "管理员隔离、原因填 description_poison", Status: "quarantined", ReviewedBy: "user_admin", Reason: "description_poison", WantAdministrator: true},
	{Name: "管理员隔离、自由文本原因", Status: "quarantined", ReviewedBy: "user_admin", Reason: "供应商下线", WantAdministrator: true},
	{Name: "管理员撤销", Status: "revoked", ReviewedBy: "user_admin", Reason: "manual_revoked", WantAdministrator: true},
	{Name: "系统隔离 Schema 变化", Status: "quarantined", ReviewedBy: SourceSystem, Reason: "rug_pull_schema_changed", WantAdministrator: false},
	{Name: "系统隔离投毒", Status: "quarantined", ReviewedBy: SourceSystem, Reason: "description_poison", WantAdministrator: false},
}
