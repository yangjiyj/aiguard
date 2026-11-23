package repository

import (
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
)

// DominantSecurityFinding is shared by live alert attribution and database-backed
// daily counts. It never modifies the supplied summary or returns a copy of evidence.
func DominantSecurityFinding(summary map[string]any) map[string]any {
	if summary == nil {
		return nil
	}
	findings, _ := summary["findings"].([]any)
	var best map[string]any
	bestRank, bestFact, bestConf, bestKey := -1, -1, -1.0, ""
	for _, raw := range findings {
		fm, ok := raw.(map[string]any)
		if !ok || !dailyFindingCountsAsSecurityFinding(fm) {
			continue
		}
		sev, _ := fm["severity"].(string)
		rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}[strings.ToLower(strings.TrimSpace(sev))]
		conf, _ := dailyFindingConfidence(fm["confidence"])
		fact := 0
		typ, _ := fm["type"].(string)
		verified, _ := fm["verified_fact"].(bool)
		if typ == "secret" || verified {
			fact = 1
		}
		if category, _ := fm["category"].(string); strings.HasPrefix(category, "agent_canary") {
			fact = 2
		}
		key := fmt.Sprint(fm["type"], "|", fm["category"], "|", fm["rule_id"], "|", fm["rule_name"])
		if rank > bestRank || (rank == bestRank && (fact > bestFact || (fact == bestFact && (conf > bestConf || (conf == bestConf && key < bestKey))))) {
			best, bestRank, bestFact, bestConf, bestKey = fm, rank, fact, conf, key
		}
	}
	return best
}

func dailyFindingCountsAsSecurityFinding(fm map[string]any) bool {
	value, present := fm["counts_as_security_finding"]
	if !present {
		return true
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return !strings.EqualFold(strings.TrimSpace(v), "false")
	default:
		return true
	}
}
func dailyFindingConfidence(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// SecurityFindingDailyDimension takes the winning finding's own category or rule
// id. A legacy top-level category is only used when structured findings are absent.
func SecurityFindingDailyDimension(summary map[string]any) string {
	if fm := DominantSecurityFinding(summary); fm != nil {
		if category, _ := fm["category"].(string); category != "" {
			return category
		}
		if id, _ := fm["rule_id"].(string); id != "" {
			return id
		}
		return ""
	}
	if findings, _ := summary["findings"].([]any); len(findings) > 0 {
		return ""
	}
	category, _ := summary["category"].(string)
	return category
}

// PrimaryFindingByIndex 返回 primary_finding.findings_index 指向的 findings 条目（2.9.22 起网关、正向代理写入，
// 主命中由数据面选定，原文只在 findings 里）。没有引用或引用无效时返回 nil，调用方再自行选取。
func PrimaryFindingByIndex(summary map[string]any) map[string]any {
	primary, _ := summary["primary_finding"].(map[string]any)
	if primary == nil {
		return nil
	}
	var index int
	switch value := primary[alertevidence.FieldFindingsIndex].(type) {
	case float64:
		if value != float64(int(value)) {
			return nil
		}
		index = int(value)
	case int:
		index = value
	default:
		return nil
	}
	findings, _ := summary["findings"].([]any)
	if index < 0 || index >= len(findings) {
		return nil
	}
	finding, _ := findings[index].(map[string]any)
	return finding
}
