package providers

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const bootstrapBudgetMaxLua = `
local function normalize_integer(value)
  if not string.match(value, '^%d+$') then
    return nil
  end
  local normalized = string.gsub(value, '^0+', '')
  if normalized == '' then
    return '0'
  end
  return normalized
end

local function greater_integer(candidate, current)
  if string.len(candidate) ~= string.len(current) then
    return string.len(candidate) > string.len(current)
  end
  return candidate > current
end

local function set_integer_max(field, candidate_raw)
	local candidate = normalize_integer(candidate_raw)
	if not candidate then
		error('invalid bootstrap integer for ' .. field)
  end
  local current_raw = redis.call('HGET', KEYS[1], field)
  if not current_raw then
    redis.call('HSET', KEYS[1], field, candidate)
    return
  end
	local current = normalize_integer(current_raw)
	if not current then
		error('invalid existing budget integer for ' .. field)
  end
  if greater_integer(candidate, current) then
    redis.call('HSET', KEYS[1], field, candidate)
  end
end

set_integer_max('requests', ARGV[1])
set_integer_max('tokens', ARGV[2])
local candidate_cost = tonumber(ARGV[3])
if not candidate_cost or candidate_cost < 0 then
	error('invalid bootstrap cost')
end
local current_cost_raw = redis.call('HGET', KEYS[1], 'cost')
if not current_cost_raw then
  redis.call('HSET', KEYS[1], 'cost', ARGV[3])
else
  local current_cost = tonumber(current_cost_raw)
	if not current_cost or current_cost < 0 then
		error('invalid existing budget cost')
  end
  if candidate_cost > current_cost then
    redis.call('HSET', KEYS[1], 'cost', ARGV[3])
  end
end
set_integer_max('cost_micros', ARGV[4])
set_integer_max('cost_estimated_requests', ARGV[5])
set_integer_max('cost_unpriced_requests', ARGV[6])
return 1
`

// BootstrapUsageFromDB 在 gateway-core 启动时从 request_logs 按各策略 IANA
// 时区回填当日和当月 Redis budget 计数，并保留 Asia/Shanghai 旧 key。
//
// 背景: Redis 的 requests/tokens/cost 是 gateway-core 运行时 HINCRBY 累加的内存态，
// 容器重启即清零。Dashboard 的"今日请求/Token"读 Redis 实时快照，重启后会显示个位数，
// 掩盖 DB 里真实的累计值(此前靠前端 Math.max 兜底，但 rollup 也有 1 小时滞后)。
//
// 本方法扫 DB 当月聚合，并用单条 Lua 对每个日/月桶做字段级单调 max：
//   - 幂等：重复执行不会双倍计数。
//   - 与运行时 HINCR 不冲突：SELECT 后到写入前出现的更高 Redis 值不会被旧快照覆盖。
//   - 5 个维度：tenant/team/project/user/client(对应 key 维度，DB 列 client_id)。
//     team 通过 request_logs 的 tenant_id + project_id 关联 projects 回填。
//
// 任一 scope 查询或 Redis 写入失败都会返回错误；启动入口在 governor 启用时
// fail-close，只有显式 UAG_GOVERNOR_DISABLED=true 才允许跳过回填。
func BootstrapUsageFromDB(ctx context.Context, db *pgxpool.Pool, rdb *redis.Client) error {
	if db == nil || rdb == nil {
		return fmt.Errorf("bootstrap: db or redis is nil")
	}
	timezones, err := bootstrapQuotaTimezones(ctx, db)
	if err != nil {
		return err
	}
	pipe := rdb.Pipeline()
	totalKeys := 0
	for _, timezone := range timezones {
		count, err := queueBootstrapTimezone(ctx, db, pipe, timezone)
		if err != nil {
			return err
		}
		totalKeys += count
	}

	if totalKeys == 0 {
		log.Printf("[budget.bootstrap] 当前配额周期无回填数据(可能确实无流量)")
		return nil
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return fmt.Errorf("budget.bootstrap pipeline exec: %w", err)
	}
	log.Printf("[budget.bootstrap] 已从 DB 回填 %d 个时区的 %d 个 budget key", len(timezones), totalKeys)
	return nil
}

func bootstrapQuotaTimezones(ctx context.Context, db *pgxpool.Pool) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT DISTINCT COALESCE(NULLIF(BTRIM(quota_timezone), ''), 'Asia/Shanghai')
		FROM quota_policies
		WHERE status='active'
	`)
	if err != nil {
		return nil, fmt.Errorf("budget.bootstrap query timezones: %w", err)
	}
	defer rows.Close()
	unique := map[string]struct{}{"Asia/Shanghai": {}}
	for rows.Next() {
		var timezone string
		if err := rows.Scan(&timezone); err != nil {
			return nil, fmt.Errorf("budget.bootstrap scan timezone: %w", err)
		}
		timezone = strings.TrimSpace(timezone)
		if _, err := time.LoadLocation(timezone); err != nil {
			return nil, fmt.Errorf("budget.bootstrap invalid timezone %q: %w", timezone, err)
		}
		unique[timezone] = struct{}{}
		if len(unique) > 64 {
			return nil, fmt.Errorf("budget.bootstrap has more than 64 active quota timezones")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("budget.bootstrap iterate timezones: %w", err)
	}
	timezones := make([]string, 0, len(unique))
	for timezone := range unique {
		timezones = append(timezones, timezone)
	}
	sort.Strings(timezones)
	return timezones, nil
}

func queueBootstrapTimezone(ctx context.Context, db *pgxpool.Pool, pipe redis.Pipeliner, timezone string) (int, error) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return 0, err
	}
	now := time.Now().In(location)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, location)
	monthBucket := quotaPeriodBucket(timezone, monthStart.Format("2006-01"))
	dayBucket := quotaPeriodBucket(timezone, todayStart.Format("2006-01-02"))
	scopes := []struct {
		scope, idExpr, joinClause, policyMatch string
	}{
		{scope: "tenant", idExpr: "rl.tenant_id", policyMatch: "TRUE"},
		{scope: "team", idExpr: "team_scope.id", joinClause: `JOIN projects p ON p.id = rl.project_id AND p.tenant_id = rl.tenant_id
			JOIN teams direct_team ON direct_team.id = p.team_id AND direct_team.tenant_id = p.tenant_id
			CROSS JOIN LATERAL unnest(string_to_array(trim(BOTH '/' FROM direct_team.path), '/')) WITH ORDINALITY path_id(id, ord)
			JOIN teams team_scope ON team_scope.id = path_id.id AND team_scope.tenant_id = direct_team.tenant_id`,
			policyMatch: "COALESCE(quota_scope.scope_ref,'') = team_scope.id"},
		{scope: "project", idExpr: "rl.project_id", policyMatch: "COALESCE(quota_scope.project_id,'') = rl.project_id"},
		{scope: "user", idExpr: "rl.actor_user_id", policyMatch: "COALESCE(quota_scope.user_id,'') = rl.actor_user_id"},
		{scope: "key", idExpr: "rl.client_id", policyMatch: "COALESCE(quota_scope.key_id,'') = rl.client_id"},
	}
	totalKeys := 0
	for _, scope := range scopes {
		query := fmt.Sprintf(`
			SELECT COALESCE(%s, '') AS id,
			       COUNT(*)::bigint,
			       COALESCE(SUM(COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0)),0)::bigint,
			       COALESCE(SUM(COALESCE(rl.total_cost,0)),0)::float8,
			       COALESCE(SUM(COALESCE(buf.billable_amount_micros,0)),0)::bigint,
			       COUNT(*) FILTER (WHERE COALESCE(rl.output_audit_result->'response_metadata'->>'usage_source','') LIKE 'estimated%%')::bigint,
			       COUNT(*) FILTER (WHERE rl.request_status IN ('success','incomplete') AND buf.billable_amount_micros IS NULL)::bigint,
			       COUNT(*) FILTER (WHERE rl.created_at >= $2)::bigint,
			       COALESCE(SUM(COALESCE(rl.input_tokens,0) + COALESCE(rl.output_tokens,0)) FILTER (WHERE rl.created_at >= $2),0)::bigint,
			       COALESCE(SUM(COALESCE(rl.total_cost,0)) FILTER (WHERE rl.created_at >= $2),0)::float8,
			       COALESCE(SUM(COALESCE(buf.billable_amount_micros,0)) FILTER (WHERE rl.created_at >= $2),0)::bigint,
			       COUNT(*) FILTER (WHERE rl.created_at >= $2 AND COALESCE(rl.output_audit_result->'response_metadata'->>'usage_source','') LIKE 'estimated%%')::bigint,
			       COUNT(*) FILTER (WHERE rl.created_at >= $2 AND rl.request_status IN ('success','incomplete') AND buf.billable_amount_micros IS NULL)::bigint
			FROM request_logs rl
			%s
			LEFT JOIN billing_usage_facts buf ON buf.tenant_id=rl.tenant_id AND buf.request_id=rl.request_id AND buf.status='settled'
				WHERE rl.created_at >= $1 AND rl.created_at < $3 AND COALESCE(%s, '') <> ''
				  AND ($4 = 'Asia/Shanghai' OR EXISTS (
				    SELECT 1 FROM quota_policies quota_scope
				    WHERE quota_scope.tenant_id = rl.tenant_id
				      AND quota_scope.status = 'active'
				      AND quota_scope.scope_type = $5
				      AND COALESCE(NULLIF(BTRIM(quota_scope.quota_timezone),''),'Asia/Shanghai') = $4
				      AND %s
				  ))
				GROUP BY %s
			`, scope.idExpr, scope.joinClause, scope.idExpr, scope.policyMatch, scope.idExpr)
		rows, err := db.Query(ctx, query, monthStart, todayStart, now, timezone, scope.scope)
		if err != nil {
			return 0, fmt.Errorf("budget.bootstrap query %s timezone %s: %w", scope.scope, timezone, err)
		}
		for rows.Next() {
			var id string
			var monthRequests, monthTokens, monthCostMicros, monthEstimated, monthUnpriced int64
			var dayRequests, dayTokens, dayCostMicros, dayEstimated, dayUnpriced int64
			var monthCost, dayCost float64
			if err := rows.Scan(&id, &monthRequests, &monthTokens, &monthCost, &monthCostMicros, &monthEstimated, &monthUnpriced,
				&dayRequests, &dayTokens, &dayCost, &dayCostMicros, &dayEstimated, &dayUnpriced); err != nil {
				rows.Close()
				return 0, fmt.Errorf("budget.bootstrap scan %s timezone %s: %w", scope.scope, timezone, err)
			}
			if id == "" {
				continue
			}
			queueBootstrapBudgetMax(ctx, pipe, BudgetKey(scope.scope, id, monthBucket), monthRequests, monthTokens, monthCost, monthCostMicros, monthEstimated, monthUnpriced)
			queueBootstrapBudgetMax(ctx, pipe, BudgetKeyDay(scope.scope, id, dayBucket), dayRequests, dayTokens, dayCost, dayCostMicros, dayEstimated, dayUnpriced)
			totalKeys += 2
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, fmt.Errorf("budget.bootstrap rows %s timezone %s: %w", scope.scope, timezone, err)
		}
	}
	return totalKeys, nil
}

func queueBootstrapBudgetMax(
	ctx context.Context,
	pipe redis.Pipeliner,
	key string,
	requests, tokens int64,
	cost float64,
	costMicros, estimatedRequests, unpricedRequests int64,
) {
	pipe.Eval(ctx, bootstrapBudgetMaxLua, []string{key},
		strconv.FormatInt(requests, 10),
		strconv.FormatInt(tokens, 10),
		strconv.FormatFloat(cost, 'f', -1, 64),
		strconv.FormatInt(costMicros, 10),
		strconv.FormatInt(estimatedRequests, 10),
		strconv.FormatInt(unpricedRequests, 10),
	)
}
