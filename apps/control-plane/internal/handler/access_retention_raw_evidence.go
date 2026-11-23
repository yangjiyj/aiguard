package handler

import (
	"context"
	"log"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// blockedInputEvidenceLookup 查询给定请求里哪些在原文留证表中有“输入方向、已阻断”记录。
type blockedInputEvidenceLookup func(ctx context.Context, tenantID string, requestIDs []string) (map[string]struct{}, error)

// fillBlockedInputEvidenceRequestIDs 给每个回合填上它的请求里有输入被阻断原文留证的那些编号，保持 request_ids 的先后顺序。
func fillBlockedInputEvidenceRequestIDs(turns []types.AccessRetentionTurnInfo, withEvidence map[string]struct{}) {
	if len(withEvidence) == 0 {
		return
	}
	for index := range turns {
		var ids []string
		for _, id := range turns[index].RequestIDs {
			if _, ok := withEvidence[id]; ok {
				ids = append(ids, id)
			}
		}
		turns[index].BlockedInputEvidenceRequestIDs = ids
	}
}

// attachBlockedInputEvidenceRequestIDs 仅对有权查看原文留证的角色，一次查完所有回合的请求编号。
// 查询失败（含老库没有留证表）只当作没有留证，不影响对话留证接口。
func attachBlockedInputEvidenceRequestIDs(ctx context.Context, user *repository.User, turns []types.AccessRetentionTurnInfo, lookup blockedInputEvidenceLookup) {
	if !canViewRawEvidenceUser(user) || len(turns) == 0 {
		return
	}
	seen := map[string]bool{}
	var ids []string
	for _, turn := range turns {
		for _, id := range turn.RequestIDs {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	withEvidence, err := lookup(ctx, user.TenantID, ids)
	if err != nil {
		log.Printf("retention turns: raw evidence lookup failed: %v", err)
		return
	}
	fillBlockedInputEvidenceRequestIDs(turns, withEvidence)
}
