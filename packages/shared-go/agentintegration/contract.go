package agentintegration

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
)

var ErrNotFound = errors.New("integration object not found")
var ErrConflict = errors.New("integration version or binding conflict")
var ErrInvalid = errors.New("invalid integration request")

// HeartbeatInterval 是网关实例心跳（integration_gateway_instances.last_seen_at）的写入间隔。
// 旧实现每 3 秒写一次（每台网关一天约 2.88 万次写）；现降到 30 秒（约 2880 次）。
// 实例的执行模式（record/protect）变化、进程重启时不受此间隔限制，立即写。
const HeartbeatInterval = 30 * time.Second

// Freshness 是状态页判定网关实例「在线」的窗口：last_seen_at 距今超过它即判 stale。
// 约束：必须 >= 2 * HeartbeatInterval，否则一次心跳写入延迟（现场磁盘偶发卡顿几十秒）就会把健康网关误判为离线。
// 取 3 个心跳间隔；代价是网关真正宕机后，状态页最长需要 90 秒（旧为 9 秒）才从 applied 转为 stale。
const Freshness = 3 * HeartbeatInterval

type Credential struct {
	ModelRestriction        string     `json:"model_restriction"`
	ModelAllowlist          []string   `json:"model_allowlist"`
	Enforcement             string     `json:"enforcement"`
	EffectiveEnforcement    string     `json:"effective_enforcement"`
	DLPEnforcement          string     `json:"dlp_enforcement"`
	EffectiveDLPEnforcement string     `json:"effective_dlp_enforcement"`
	EnforcementGate         string     `json:"enforcement_gate"`
	KeyID                   string     `json:"key_id"`
	AgentInstanceID         string     `json:"agent_instance_id"`
	ProjectID               string     `json:"project_id"`
	Name                    string     `json:"name"`
	KeyPrefix               string     `json:"key_prefix"`
	Scopes                  []string   `json:"scopes"`
	Status                  string     `json:"status"`
	CreatedAt               time.Time  `json:"created_at"`
	ExpiresAt               *time.Time `json:"expires_at"`
}

type Policy struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"-"`
	AgentInstanceID string    `json:"agent_instance_id"`
	Action          string    `json:"action"`
	Enabled         bool      `json:"enabled"`
	Mode            string    `json:"mode"`
	MCPServerID     string    `json:"mcp_server_id"`
	Version         string    `json:"version"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Instance struct {
	InstanceID string    `json:"instance_id"`
	BootID     string    `json:"boot_id"`
	LastSeenAt time.Time `json:"last_seen_at"`
	Mode       string    `json:"mode"`
}

type RuleHits struct {
	RuleID       string `json:"rule_id"`
	HitCount     int64  `json:"hit_count"`
	BlockedCount int64  `json:"blocked_count"`
}

type Receipt struct {
	InstanceID    string     `json:"instance_id"`
	BootID        string     `json:"boot_id"`
	LoadedVersion string     `json:"loaded_version"`
	LoadedAt      *time.Time `json:"loaded_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	Status        string     `json:"status"`
	HitCount      int64      `json:"hit_count"`
	BlockedCount  int64      `json:"blocked_count"`
	RuleHits      []RuleHits `json:"rule_hits"`
}

type Status struct {
	PolicyID            string    `json:"policy_id"`
	AgentInstanceID     string    `json:"agent_instance_id"`
	DesiredVersion      string    `json:"desired_version"`
	ExpectedVersion     string    `json:"expected_version"`
	Status              string    `json:"status"`
	EnforcementVerified bool      `json:"enforcement_verified"`
	Reason              string    `json:"reason"`
	Instances           []Receipt `json:"instances"`
}

func ValidID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func ValidatePolicy(p Policy) error {
	if !ValidID(p.AgentInstanceID) || (p.Action != "block_model_egress" && p.Action != "disable_mcp") || (p.Mode != "record" && p.Mode != "protect") {
		return ErrInvalid
	}
	if p.MCPServerID != "" && (!ValidID(p.MCPServerID) || p.Action != "disable_mcp") {
		return ErrInvalid
	}
	return nil
}

func SafeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	u.ForceQuery = false
	return u.String()
}

func EvaluateStatus(p Policy, nodes []Instance, receipts []Receipt, expected []string, version string, requireHit bool, now time.Time) Status {
	if version == "" {
		version = p.Version
	}
	result := Status{PolicyID: p.ID, AgentInstanceID: p.AgentInstanceID, DesiredVersion: p.Version, ExpectedVersion: version, Status: "pending", Reason: "gateway_receipt_pending", Instances: []Receipt{}}
	byID := map[string]Receipt{}
	for _, r := range receipts {
		byID[r.InstanceID] = r
	}
	seen := map[string]bool{}
	verified := len(nodes) > 0 && version == p.Version
	failure := ""
	for _, n := range nodes {
		seen[n.InstanceID] = true
		r, found := byID[n.InstanceID]
		r.InstanceID, r.LastSeenAt = n.InstanceID, n.LastSeenAt
		if r.RuleHits == nil {
			r.RuleHits = []RuleHits{}
		}
		switch {
		case now.Sub(n.LastSeenAt) > Freshness || n.LastSeenAt.After(now.Add(time.Second)) || (r.LoadedAt != nil && r.LoadedAt.After(now.Add(time.Second))):
			r.Status = "stale"
		case !found || r.BootID != n.BootID || r.LoadedAt == nil:
			r.BootID, r.LoadedVersion, r.LoadedAt = n.BootID, "", nil
			r.HitCount, r.BlockedCount, r.RuleHits = 0, 0, []RuleHits{}
			r.Status = "pending"
		case version != p.Version || r.LoadedVersion != version:
			r.Status = "version_mismatch"
		case !p.Enabled || p.Mode != "protect" || n.Mode != "protect":
			r.Status = "record_only"
		case requireHit && r.BlockedCount == 0:
			r.Status = "waiting_for_hit"
		default:
			r.Status = "applied"
		}
		if r.Status != "applied" {
			verified = false
			if failure == "" {
				failure = r.Status
			}
		}
		result.Instances = append(result.Instances, r)
	}
	for _, id := range expected {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			verified = false
			failure = "pending"
			result.Instances = append(result.Instances, Receipt{InstanceID: id, Status: "pending", RuleHits: []RuleHits{}})
		}
	}
	sort.Slice(result.Instances, func(i, j int) bool { return result.Instances[i].InstanceID < result.Instances[j].InstanceID })
	if version != p.Version {
		failure = "version_mismatch"
	}
	if verified {
		result.Status, result.Reason, result.EnforcementVerified = "applied", "", true
	} else if failure != "" {
		result.Status, result.Reason = failure, "gateway_"+failure
	}
	return result
}
