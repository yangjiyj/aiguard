# chat-portal 集成通道对接契约（portal-integration API）

本文档面向 chat-portal（员工 SSO Chat 门户）后端的对接方，描述网关控制面 `/admin/v1/portal-integration/*` 机器对机器通道的认证方式、端点契约、错误码，以及数据面 `X-Security-Action` 响应头契约。

- **服务端：** control-plane（默认 `:8081`）
- **认证模型：** 共享密钥（shared secret），与管理台会话认证完全隔离
- **门控开关：** 环境变量 `NEWAPI_PORTAL_API_SECRET`，**留空 = 通道关闭**（该组全部端点返回 503），对既有部署零影响

## 认证

### 共享密钥

所有 `/admin/v1/portal-integration/*` 端点由 `PortalIntegrationAPIMiddleware` 保护，密钥来自环境变量 `NEWAPI_PORTAL_API_SECRET`。以下两种携带方式**任选其一**：

```
X-NewAPI-Internal-Token: <NEWAPI_PORTAL_API_SECRET>
```

```
Authorization: Bearer <NEWAPI_PORTAL_API_SECRET>
```

认证失败语义（fail-closed）：

| 场景 | HTTP 状态码 | 错误码 (code) |
|------|-------------|----------------|
| 服务端未配置密钥（env 为空） | 503 | internal_auth_not_configured |
| 请求未带密钥或密钥不匹配 | 401 | unauthorized |

**密钥隔离约束：** `NEWAPI_PORTAL_API_SECRET` 与 `NEWAPI_INTERNAL_API_SECRET` 相互独立、无 fallback。门户后端拿到的凭据不能调用 `/admin/v1/internal/*` 与 `/admin/v1/eval-integration/*` 端点，反之亦然。请为门户签发独立的长随机密钥，不要复用内部密钥。

### 租户上下文（X-NewAPI-Tenant-Id）

除 `health` 外，所有端点必须携带租户头：

```
X-NewAPI-Tenant-Id: tenant_default
```

缺失或为空白时返回 `400 tenant_required`。跨租户访问资源（项目 / 团队 / key 不属于该租户）一律返回 `404 not_found` 掩蔽，不泄漏资源是否存在。

## 通用约定

- **错误响应格式：** 所有错误统一为 `{"error": {"code": "<错误码>", "message": "<说明>"}}`。
- **时间格式：** 请求与响应中的时间戳均为 RFC 3339（如 `2026-08-01T00:00:00+08:00`）；用量端点的日期参数为 `YYYY-MM-DD`（按 Asia/Shanghai 日界）。
- **依赖未就绪：** 服务内部依赖未配置时返回 `503 portal_integration_not_configured`。
- **内部错误：** 仓库既有约定下，`internal_error` 错误码随 HTTP 400 返回（个别端点使用独立错误码与 500，见各端点说明）。
- **审计留痕：** 门户侧写操作（建 key / 吊销 key）落 `audit_operations` 表，`user_id` 为 NULL，服务身份 `portal-integration` 与租户 ID 记录在 `action_detail` 中。

## 端点契约

### 1. 健康探活

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/health`
- **租户头：** 不需要

响应（200）：

```json
{"status": "ok", "service": "portal-integration"}
```

中间件已验密钥，能收到 200 即代表通道可用。可作为部署后连通性自检的第一站。

### 2. 创建 key

- **请求方式：** POST
- **请求路径：** `/admin/v1/portal-integration/keys`
- **Content-Type：** application/json

请求参数：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| project_id | string | 是 | 项目 ID，必须属于当前租户 |
| user_id | string | 否 | key 归属用户 ID；留空 = 无归属（机器通道没有「当前用户」可默认）；填写时必须属于当前租户 |
| scopes | string[] | **是（且非空）** | 权限范围，取值：`*` / `chat` / `responses` / `embeddings` / `models`。**与会话端不同，门户建 key 必须显式声明**——空 scopes 在数据面等于全放行，机器通道禁止 |
| name | string | 否 | key 名称/备注（如「张三/研发部」），按字符计最长 128，用于审计按人追溯 |
| expires_at | string | 否 | 过期时间，RFC 3339，必须是未来时间；留空 = 永不过期。数据面在认证时拦截过期 key |

请求示例：

```json
{
  "project_id": "project_default",
  "user_id": "user_zhangsan",
  "scopes": ["chat", "models"],
  "name": "张三/研发部",
  "expires_at": "2026-08-01T00:00:00+08:00"
}
```

响应示例（200）：

```json
{
  "id": "key_1a2b3c4d",
  "project_id": "project_default",
  "user_id": "user_zhangsan",
  "name": "张三/研发部",
  "key_prefix": "na_1234",
  "scopes": ["chat", "models"],
  "full_key": "na_<仅在创建响应中返回的完整密钥>",
  "status": "active",
  "created_at": "2026-07-02T10:30:00Z",
  "expires_at": "2026-07-31T16:00:00Z"
}
```

> **full_key 一次性语义：** 完整密钥 `full_key` **仅在创建响应中返回这一次**，服务端只存哈希，之后任何接口（含列表）都无法再取回。门户后端必须在本次响应中把 `full_key` 交付给员工或安全存储；丢失只能吊销重建。

错误码：

| HTTP 状态码 | 错误码 | 触发条件 |
|-------------|--------|----------|
| 400 | tenant_required | 缺租户头 |
| 400 | invalid_request | JSON 不合法 / scope 不在白名单 / name 超长 / expires_at 非 RFC 3339 或非未来时间 / user_id 不属于该租户 |
| 400 | scopes_required | scopes 缺失或为空数组 |
| 404 | not_found | 项目不存在或不属于该租户 |
| 503 | portal_integration_not_configured | 服务内部依赖未就绪 |

### 3. 列出 key

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/keys`

请求参数（query）：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| project_id | string | 是 | 按项目列出（门户按项目管理，不提供整租户全量） |

响应（200）：`{"data": [KeyInfo], "total": <数量>}`。`KeyInfo` 字段同「创建 key」响应，但**不含 `full_key`**。

错误码：`400 tenant_required` / `400 invalid_request`（缺 project_id）/ `400 internal_error` / `503 portal_integration_not_configured`。

### 4. 吊销 key

- **请求方式：** POST
- **请求路径：** `/admin/v1/portal-integration/keys/{id}/revoke`

路径参数 `id` 为 key ID（非 key 明文）。成功返回 **204 No Content**，吊销立即生效（数据面认证拒绝）。

错误码：

| HTTP 状态码 | 错误码 | 触发条件 |
|-------------|--------|----------|
| 400 | tenant_required | 缺租户头 |
| 404 | not_found | key 不存在或不属于该租户（掩蔽语义） |
| 400 | internal_error | 内部错误 |

### 5. 按 key 用量

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/usage/by-key`

请求参数（query）：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| start_date | string | 否 | 起始日期 `YYYY-MM-DD`（Asia/Shanghai 日界），别名 `from`；默认最近 30 天 |
| end_date | string | 否 | 结束日期 `YYYY-MM-DD`（含当日），别名 `to` |

响应（200）为按 key 聚合的用量数组（租户全量口径）：

> **`name` 字段语义注意：** 本端点响应里的 `name` 是 **key 前缀**（与 `key_prefix` 相同，历史聚合口径），**不是**建 key 时填写的员工名。要展示员工名，请用「列出 key」端点返回的 `name` 按 `id` 自行关联。

```json
[
  {
    "id": "key_1a2b3c4d",
    "name": "na_1234",
    "key_prefix": "na_1234",
    "project_id": "project_default",
    "user_id": "user_zhangsan",
    "requests": 132,
    "input_tokens": 51200,
    "output_tokens": 20480,
    "total_tokens": 71680,
    "total_cost": 3.52,
    "cost_percent": 12.5,
    "average_cost": 0.026,
    "success_rate": 99.2
  }
]
```

错误码：`400 tenant_required` / `400 internal_error` / `503 portal_integration_not_configured`。

### 6. 团队模型授权

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/teams/{id}/models`

响应（200）：`{"data": [TeamModel]}`，每项含 `team_id` / `model_id` / `allowed` / `daily_token_limit`（可选）/ `granted_by` / `granted_at`。

错误码：`400 tenant_required` / `404 not_found`（团队不存在或不属于该租户）/ `400 internal_error` / `503 portal_integration_not_configured`。

### 7. 团队生效配置（effective）

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/teams/{id}/effective`

响应（200）：

```json
{
  "team": { "...": "团队信息（含预算）" },
  "members": [ { "...": "团队成员" } ],
  "models": [ { "...": "模型授权，同上一端点" } ],
  "projects": [ { "...": "团队关联项目" } ]
}
```

错误码：同「团队模型授权」。

### 8. 项目模型策略

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/policies/model`

请求参数（query）：

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| project_id | string | 是 | 项目 ID |

响应（200）：

```json
{
  "id": "mp_9f8e7d",
  "tenant_id": "tenant_default",
  "project_id": "project_default",
  "allow_list": ["gpt-4o", "deepseek-chat"],
  "deny_list": []
}
```

项目无策略时返回空默认值（`allow_list` / `deny_list` 均为空数组，`id` / `tenant_id` 为空），语义为「不限制」。

错误码：`400 tenant_required` / `400 invalid_request`（缺 project_id）/ `400 internal_error` / `503 portal_integration_not_configured`。

### 9. 模型清单

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/models`

响应（200）：`{"data": [ModelInfo], "total": <数量>}`，每项含 `id` / `provider_id` / `model_name` / `model_label` / `pricing_json` / `proxy_config` / `status` / `created_at` 等，与会话端 `GET /admin/v1/models` 响应结构一致。

错误码：`400 tenant_required` / `400 internal_error` / `503 portal_integration_not_configured`。

### 10. 安全事件查询（audit-events）

- **请求方式：** GET
- **请求路径：** `/admin/v1/portal-integration/audit-events`

返回安全事件摘要（不导出完整请求/响应原文），供门户向员工展示「你的请求为什么被处置」。

> **`matched_summary` 内容注意：** 除示例展示的 `source` / `category` 外，`matched_summary.findings[]` 还可能含 `matched_location`、`redacted_evidence`、`matched_text_preview` 等字段，其中 `matched_text_preview` 是命中文本预览，**可能包含命中原文片段**（同租户数据）。门户展示层建议只取 `category` / `action_taken` / `severity`，不要把 `matched_summary` 原样渲染给员工。

请求参数（query，全部可选）：

| 参数名 | 类型 | 说明 |
|--------|------|------|
| user_id | string | 按用户过滤（匹配事件或所属请求日志上的 user_id） |
| client_id | string | 按 key ID 过滤，别名 `key_id` |
| severity | string | 按严重度过滤（如 `low` / `medium` / `high` / `critical`）；值不校验，拼写错误会静默返回空集 |
| event_type | string | 按事件类型过滤 |
| start_time | string | 起始时间，RFC 3339 或 `YYYY-MM-DD`，别名 `start` / `start_date` / `from` |
| end_time | string | 结束时间，同上，别名 `end` / `end_date` / `to` |
| limit | int | 每页条数，默认 100，上限 500 |
| cursor | string | 分页游标（首版为数字 offset）；响应含 `total`，下一页传 `当前 offset + 本页条数`，直至取满 |

> **默认时间窗：** 未显式给出时间参数时，强制套用**最近 24 小时**窗口（机器通道轮询语义，防全表扫描）。需要更早的数据请显式传 `start_time` / `end_time`。

响应示例（200）：

```json
{
  "data": [
    {
      "id": "se_5f6a7b",
      "request_id": "req_0c1d2e",
      "event_type": "pii_detected",
      "severity": "high",
      "rule_id": "builtin_pii_idcard",
      "rule_name": "身份证号检测",
      "rule_type": "builtin",
      "action_taken": "audit",
      "matched_summary": {"source": "gateway", "category": "pii"},
      "created_at": "2026-07-02T09:15:00Z"
    }
  ],
  "total": 1
}
```

错误码：

| HTTP 状态码 | 错误码 | 触发条件 |
|-------------|--------|----------|
| 400 | tenant_required | 缺租户头 |
| 400 | invalid_limit | limit 非正整数或超过 500 |
| 400 | invalid_cursor | cursor 非法 |
| 400 | invalid_time_range | 时间参数无法解析 |
| 500 | security_event_query_failed | 查询失败 |
| 503 | portal_integration_not_configured | 依赖未就绪 |

### 11. 会话端安全事件过滤增强（既有端点）

- **请求方式：** GET
- **请求路径：** `/admin/v1/audit/events`（管理台会话认证，**非** portal 组）

既有端点本次新增**可选**过滤参数 `user_id` / `client_id` / `severity` / `event_type`，语义与上一端点一致。向后兼容约定：

- 不传任何新参数 = 原行为，逐条分页（`limit` / `offset`）语义不变；
- **不套默认 24 小时时间窗**（与 portal 端点刻意不同），保持既有分页浏览体验。

## X-Security-Action 响应头契约（数据面）

gateway-core 数据面（默认 `:8080`）在响应中回带本次请求**实际执行的最强安全动作**，供 chat-portal 向员工做处置提示。

> **开关：** 此头由 gateway-core 的 `SECURITY_ACTION_HEADER_ENABLED` 门控，**默认 `true`（开）**，门户可直接消费。注意：audit_only 模式下该头对数据面客户端等于检测预言机（探测方可得知哪些 payload 触发检测），数据面对不可信客户端暴露的部署可置 `false` 关闭——届时门户的处置提示（F4）将不可用。

### 取值与优先级

| 取值 | 含义 |
|------|------|
| block | 请求或输出被拦截（含工具调用拦截 `tool_blocked`） |
| reply | 安全回复替换（拦截并返回固定安全话术） |
| mask | 内容脱敏（命中后打码放行） |
| audit | 仅审计留痕（含 audit_only 降级后的实际动作） |

一次请求可能命中多层检测（输入侧 + 输出侧），头只报最强动作，优先级：`block` > `reply` > `mask` > `audit`。**未命中任何安全动作时不设此头**——客户端应把「无此头」视为正常放行，不要依赖头必然存在。

### audit_only 行为（重要）

执行模式为「记录」时（新装默认；或部署设置 `SECURITY_AUDIT_ONLY=true` 锁定为记录），block / reply 等动作被降级为仅审计，**实际执行**的动作是 audit，因此头如实为 `audit` 而不是 `block`。

此头是**纯陈述性**的：只做事后陈述，绝不参与、绝不改变任何拦截 / 降级 / 钳制决策。加头改造对 `SECURITY_AUDIT_ONLY` 审计底线零触碰。

### 覆盖范围

| 数据面端点 | 覆盖情况 |
|------------|----------|
| `POST /v1/chat/completions` | 输入 / 输出、非流式 / 流式（SSE）全覆盖 |
| `POST /v1/messages` | 全覆盖 |
| `POST /v1/responses` | 全覆盖 |
| `POST /v1/embeddings` | 本期仅在 block 动作时回带，mask / audit 不回带（已知边界） |

流式（SSE）响应为 buffer-then-emit 语义：头在写出任何字节之前设置，流式拦截同样以「响应头 + SSE 错误事件」体现，客户端读头即可，无需解析流中段。

### 拦截响应状态码

| 错误类型 | HTTP 状态码 | 说明 |
|----------|-------------|------|
| security_blocked | 403 | 内容安全拦截 |
| tool_blocked | 403 | 工具调用拦截。**本次修复：** 此前误发 500，现与审计记录一致为 403 |

## 部署接线

### 环境变量清单

| 变量 | 必填 | 默认 | 说明 |
|------|------|------|------|
| NEWAPI_PORTAL_API_SECRET | 否 | 空 | portal-integration 通道共享密钥；**留空 = 通道关闭**（该组端点返回 503），既有部署无需任何变更 |

配套（既有变量，此处仅列相关项）：

| 变量 | 说明 |
|------|------|
| NEWAPI_INTERNAL_API_SECRET | gateway-core / eval-integration 内部通道密钥，**与门户密钥独立，勿复用** |
| SECURITY_AUDIT_ONLY | 只审计部署锁（默认 `false`，执行模式由控制台决定，新装为记录模式）；设为 `true` 时锁定为记录模式、控制台不能切到防护。影响 `X-Security-Action` 的实际取值（见上文） |
| SECURITY_ACTION_HEADER_ENABLED | `X-Security-Action` 头开关（gateway-core，默认 `true`=回带），不可信数据面暴露场景可置 `false` |

### docker compose

`deploy/docker-compose/docker-compose.yml` 与 `docker-compose.offline.yml` 的 control-plane 服务均已透传：

```yaml
- NEWAPI_PORTAL_API_SECRET=${NEWAPI_PORTAL_API_SECRET:-}
```

采用 `:-`（默认空）而非 `:?`（必填）：门户通道是可选功能，不阻塞既有部署的 `docker compose up`。启用时在 `.env` 中填入长随机密钥后重启 control-plane 即可。

### 数据库迁移

迁移 `deploy/migrations/100_internal_keys_name.sql`：`internal_keys` 补 `name VARCHAR(128) NOT NULL DEFAULT ''` 列，幂等可重跑、仅加列；gateway-core 数据面对该列零感知（其查询为显式列清单），升级顺序无约束。

### 快速自检

```bash
# 1. 探活（替换为实际密钥）
curl -sS -H "Authorization: Bearer $NEWAPI_PORTAL_API_SECRET" \
  http://127.0.0.1:8081/admin/v1/portal-integration/health

# 2. 建一把 1 天有效期的 key
curl -sS -X POST \
  -H "Authorization: Bearer $NEWAPI_PORTAL_API_SECRET" \
  -H "X-NewAPI-Tenant-Id: tenant_default" \
  -H "Content-Type: application/json" \
  -d '{"project_id":"project_default","scopes":["chat"],"name":"联调测试","expires_at":"'$(date -u -d "+1 day" +%Y-%m-%dT%H:%M:%SZ)'"}' \
  http://127.0.0.1:8081/admin/v1/portal-integration/keys
```
