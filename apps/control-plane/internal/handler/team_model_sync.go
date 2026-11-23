package handler

import (
	"context"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// buildModelIDNameMaps 返回租户内模型的 行ID→名 与 名→行ID 双向映射。
// team_models.model_id 存的是模型行ID（model_xxxx），model_policies.allow_models_json
// 存的是模型名（glm-5.2）；部门白名单跨这两张表必须翻译。
func buildModelIDNameMaps(ctx context.Context, deps *Dependencies, tenantID string) (idToName, nameToID map[string]string, err error) {
	models, err := deps.ModelRepo.List(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	idToName = make(map[string]string, len(models))
	nameToID = make(map[string]string, len(models))
	for _, m := range models {
		idToName[m.ID] = m.ModelName
		nameToID[m.ModelName] = m.ID
	}
	return idToName, nameToID, nil
}

// writeTeamAllowlistToProjects 把部门白名单（模型名）覆盖写到该部门名下每个应用的
// model_policies.allow_models_json（chat 读的表）。保留各应用原有 deny 列表。
// 返回被写入的 project id 列表（空 = 部门未挂应用，授权不会对 chat 生效）。
func writeTeamAllowlistToProjects(ctx context.Context, deps *Dependencies, tenantID, teamID string, allowedNames []string) ([]string, error) {
	pr, ok := deps.ProjectRepo.(*repository.ProjectRepository)
	if !ok {
		return nil, fmt.Errorf("project repo type assertion failed")
	}
	projects, err := pr.ListByTeam(ctx, tenantID, teamID)
	if err != nil {
		return nil, err
	}
	written := make([]string, 0, len(projects))
	for _, p := range projects {
		var deny []string
		if existing, _ := deps.ModelPolicyRepo.GetByProject(ctx, tenantID, p.ID); existing != nil {
			deny = existing.DenyList
		}
		if err := deps.ModelPolicyRepo.CreateOrUpdate(ctx, &repository.ModelPolicy{
			TenantID:  tenantID,
			ProjectID: p.ID,
			ScopeType: "project",
			AllowList: allowedNames,
			DenyList:  deny,
		}); err != nil {
			return written, err
		}
		written = append(written, p.ID)
	}
	return written, nil
}
