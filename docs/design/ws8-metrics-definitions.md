# W8 控制台统计口径定义

适用页面：态势总览（Dashboard）、安全运营总览、安全告警、阻断记录、操作审计、消息中心，以及上述页面导出的 Word / CSV / XLSX。
各页的数字、标题、导出报告都以本文为准；改口径先改本文。

## 1. 时区与时间窗

| 项 | 定义 |
|---|---|
| 统计时区 | 租户时区。取 `tenants.config_json->>'timezone'`（合法 IANA 名）；未配置或非法时为 `Asia/Shanghai`。后端 `GET /admin/v1/stats/overview` 以 `timezone` 字段下发，前端所有日界、自然周/月、时间显示都按该时区计算，不再用浏览器本地时区。 |
| 日界 | 租户时区 00:00。窗口一律左闭右开 `[start, end)`。 |
| 近 N 天 | `[今天00:00 - (N-1)天, 明天00:00)`，含今天共 N 个自然日。 |
| 近 24 小时 | `[now - 24h, now)`，滚动窗口，不按日界对齐。 |
| 本周 / 上周 | 自然周，周一 00:00 起（ISO 周）。 |
| 本月 / 上月 | 自然月，1 日 00:00 起。 |
| 自定义 | 用户选择的起止自然日，结束日包含在内（即 `end = 结束日次日00:00`）。 |
| 所有时间 | 起点为该租户 `usage_rollup_hourly` 最早 `bucket_start` 所在自然日（overview 的 `data_start`）；无数据时回退为今天。不再写死 2026-01-01。 |

计费分析接口单次最长 366 天，长跨度由 `utils/billingRange.ts` 切片合并，口径不变。
从安全运营总览下钻到安全告警页时一律携带显式 `start_time/end_time`；只有预设小时窗（24h/7d/…）另带 `window_hours`，自然周 / 月与自定义不带。

## 2. 用量指标（来源 `usage_rollup_hourly`，按 `bucket_start` 落窗）

| 指标 | 定义 |
|---|---|
| 请求数 | `SUM(request_count)` |
| Token 用量 | `SUM(input_tokens + output_tokens)` |
| 今日 / 昨日 | 租户时区自然日；今日值取 Redis 实时快照与 rollup 的较大值（快照重启归零时不回退）。 |
| 用户 Token 占比 | 分子：该用户在所选窗口内的 Token；分母：同一窗口、同一可见范围内**已归属用户**（`user_id <> ''`）的 Token 合计。由 `GET /stats/users?with_totals=true` 返回的 `totals` 提供，前端不再用全历史累计或固定近 30 天作分母。 |
| 用户请求占比 | 同上，分子分母均为 `request_count`。 |
| 应用调用 TOP | `usage/by-project` 在所选统计范围内按请求数排序；标题随范围变化。 |

## 3. 告警与阻断指标

| 指标 | 来源 | 定义 |
|---|---|---|
| 待处置告警 | `security/alert-occurrences/summary`，`grouping=cases&disposition=pending` | 告警问题（case）未被抑制且处置状态为 `open`。首页与安全运营总览使用同一接口、同一参数、同一时间窗；安全告警页「待处置」页签是同一集合。 |
| 告警总数 | `audit/content/security-overview` | 窗口内有可处置告警的会话数。 |
| 阻断记录 | `security_events` | `action_taken IN ('block','security_blocked','stream_blocked','tool_attempt_blocked','tool_blocked')` 且 `event_type <> 'security_check_failed'`。 |
| 执行模式 | `system_settings` | `security_execution_mode`（record / protect），部署锁 `SECURITY_AUDIT_ONLY=true` 时强制 record。overview 以 `execution_mode` 下发。 |

### action_taken 显示规则（8.8）

2026-09-29 在开发 VM 只读核实：记录模式期间（`security_audit_only=true`）落库值为 `security_audit_only` 或 `audit`，**不产生**任何阻断类值；阻断类值只在防护模式期间出现，均为真实阻断。
`security_events` 行上不存当时的执行模式，因此：

- 阻断类值如实显示为已拦截（它们只可能在防护模式下写入）。
- `security_audit_only` 统一显示为「观察留痕」放行（与执行模式名称一致），不再出现「审计模式放行 / 审计放行」两种说法。
- 页眉与导出报告写明**当前**执行模式，报告中注明「阻断数只统计真实阻断；观察留痕模式下命中规则只记录不阻断」。

## 4. 审计导出（8.7）

| 项 | 定义 |
|---|---|
| 范围 | 服务端按当前筛选条件全量导出，不受页面分页影响；单次上限 100000 行，超出时返回 413，提示缩小时间范围。 |
| 格式 | `format=csv`（UTF-8 BOM，Excel 直接打开不乱码）或 `format=xlsx`（标准库 zip 生成，单工作表）。 |
| 时间列 | 按租户时区格式化为 `YYYY-MM-DD HH:mm:ss`，表头注明时区。 |
| 留痕 | 每次导出写一条操作审计：`action_type` 为 `export_operation_audit` / `export_block_records` / `export_alert_inbox`，`action_detail` 含格式、筛选条件、行数。 |
| 可见范围 | 操作审计：平台管理员看全局，其余角色只看本租户；阻断记录：部门管理员只看本部门应用；消息中心：本租户。 |

## 5. 未覆盖项

- 8.10 安全统计的部门 / 应用 / 模型维度与处置动作分布、8.11 定时周报 / 月报推送：本轮未实现，见 `docs/changelog-fragments/ws8.md`。
