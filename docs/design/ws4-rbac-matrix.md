# W4 RBAC matrix: three-officer separation of duties

Branch `ws4-rbac-ia`, baseline 3b8a624d (2.7.1). Generated from the code tables; regenerate instead of editing by hand.

- Backend enforcement: `apps/control-plane/internal/permission/sod.go` (`SoDGuard`, always enforcing, independent of `UAG_RBAC_ENFORCE` dry-run) + `sod_routes.go` (route -> class table, one row per protected route).
- Frontend presentation: `apps/web-console/src/utils/access.ts` (`PAGE_ACCESS`, `canSeeMenuItem`, `roleHome`). Route guards (`RequireRole`) and the side menu both read it. The pre-W4 blanket `platform_admin` bypass is removed.
- `TestSoDRouteTableCoversEveryProtectedRoute` fails if a route is added to `cmd/server/main.go` without a class.

## 1. Roles

| Code | Label | Duty |
|---|---|---|
| `platform_admin` | 系统管理员 | Users, resources, billing, system configuration. Keeps security policy write (decision 2026-09-30). No audit read/write. |
| `admin` | 管理员（历史） | Legacy synonym. Migration 890 rewrites it to `platform_admin`; code treats both the same. |
| `security_officer` | 安全保密管理员 | Security policy, alert handling, evidence review. No users, system config, or audit log. |
| `auditor` | 审计员 | Read-only: operation audit, content evidence, compliance overview, login history; audit export. No business config. |

## 2. Backend: role x endpoint class

`Allow` = granted by the SoD guard (the legacy matrix is skipped). `Deny` = 403 `separation_of_duties`. `Defer` = falls through to the pre-existing RBAC/handler checks (unchanged behaviour).

| Class | Routes | SysAdmin | SecOfficer | Auditor | Other roles |
|---|---|---|---|---|---|
| `common` | 16 | Defer | Allow | Allow | Defer |
| `directory_read` | 4 | Defer | Allow | Deny | Defer |
| `security_record_read` | 32 | Defer | Allow | Allow | Defer |
| `security_config_read` | 34 | Defer | Allow | Deny | Defer |
| `security_write` | 42 | Defer | Allow | Deny | Defer |
| `alert_handle` | 2 | Defer | Allow | Deny | Defer |
| `evidence` | 16 | Deny* | Allow | Allow | Defer |
| `audit` | 3 | Deny | Deny | Allow | Deny |
| `audit_export` | 4 | Deny | Deny | Allow | Deny |
| `login_history` | 2 | Deny | Deny | Allow | Defer |
| `system` | 237 | Defer | Deny | Deny | Defer |

Total: 392 routes. `*` exception: `GET /admin/v1/audit/access-retention?summary_only=true&summary_detail=counts` (dashboard counters only, no content) stays `Defer` for the system administrator.

Handler-level changes that back this table:

- `platform_admin`-only policy handlers now accept `roles.CanManageSecurityPolicy` (platform_admin or security_officer): security_rules, tool_risk_config, security_policies, security_reply_policy, smart_detection, semantic_config, semantic_runtime_status, rule_pack_pull_status, policy_assets, agent_operation_handlers, content_security_config.
- content_evidence_authorization: security_officer added to both evidence cases.
- usage `resolveUsageScope`: `roles.IsTenantWideSecurityReader` (officers read security records tenant-wide). dept_scope `isFullTenantRole` adds only the security officer: it also gates writes (quota, budget, keys), so the auditor stays department-bound there and its writes are refused by the SoD guard.
- users / users_local_identity: the two officer roles are assignable platform roles.
- rbac_handlers: user grants require a system administrator (`canManageGrants`), officer roles cannot be granted as scoped roles, and cross-tenant targets are rejected except for system-tenant callers. New `GET /admin/v1/audit/login-history` (auditor only; tenant-scoped for non-system-tenant callers).

## 3. Frontend: page x role

`Y` = route opens. Pages not listed are open to every signed-in role.

| Path | Menu label | SysAdmin | SecOfficer | Auditor | TenantOwner | DeptMgr | Developer |
|---|---|---|---|---|---|---|---|
| `/security/policies` | 策略中心 | Y | Y | - | - | - | - |
| `/security/tool-config` | 工具调用策略 | Y | Y | - | - | - | - |
| `/security/agents` | 智能体行为管控 | Y | Y | - | Y | - | - |
| `/security/agents/advanced` | 例外与确认 | Y | Y | - | Y | - | - |
| `/security/agentguard` | 智能体安全 | Y | Y | - | Y | - | - |
| `/security/agent-operation-protection/advanced` | Agent 操作防护 | Y | Y | - | - | - | - |
| `/security/skills` | Skill 安全准入 | Y | Y | - | - | - | - |
| `/security/alerts` | 安全告警 | Y | Y | Y | Y | Y | - |
| `/security/blocks` | 阻断记录 | Y | Y | Y | Y | Y | - |
| `/security/agent-tools` | 工具调用明细 | Y | Y | Y | - | - | - |
| `/mcp-gateway/servers` | MCP 服务管理 | Y | Y | - | - | - | - |
| `/mcp-gateway/policies` | 权限策略 | Y | Y | - | - | - | - |
| `/mcp-gateway/approvals` | 审批与例外 | Y | Y | - | - | - | - |
| `/mcp-gateway/audit` | 调用审计 | Y | Y | Y | - | - | - |
| `/compliance/overview` | 合规总览 | - | Y | Y | - | - | - |
| `/audit/access-retention` | 内容留证 | - | Y | Y | - | - | - |
| `/system/audit-operations` | 操作审计 | - | - | Y | - | - | - |
| `/audit/login-history` | 登录历史 | - | - | Y | - | - | - |
| `/organizations` | 组织管理 | Y | - | - | Y | Y | - |
| `/users` | 用户管理 | Y | - | - | - | - | - |
| `/apps` | 应用管理 | Y | - | - | Y | - | - |
| `/keys` | 密钥管理 | Y | - | - | - | - | - |
| `/identity-sources` | 企业身份源 | Y | - | - | Y | - | - |
| `/identity-sources/login` |  | Y | - | - | Y | - | - |
| `/identity-sources/directory` |  | Y | - | - | Y | - | - |
| `/providers` | 模型上游 | Y | - | - | - | - | - |
| `/models` | 模型管理 | Y | - | - | - | - | - |
| `/model-routing` | 模型路由 | Y | - | - | Y | - | - |
| `/cost/customer-billing` | 计费中心 | Y | - | - | - | - | - |
| `/cost/quota-policies` | 配额与限流 | Y | - | - | Y | Y | Y |
| `/system/settings` | 系统设置 | Y | - | - | - | - | - |
| `/system/retention-storage` | 内容留存存储 | Y | - | - | - | - | - |
| `/system/license` | 授权管理 | Y | - | - | - | - | - |
| `/system/notify-channels` | 通知渠道 | Y | - | - | - | - | - |
| `/connect/channels` | 接入通道 | Y | - | - | - | - | - |
| `/connect/network` | 网络与证书 | Y | - | - | - | - | - |
| `/cost/alerts` | 消息中心 | Y | Y | Y | - | - | - |
| `/dashboard` | 态势总览 | Y | - | - | Y | Y | Y |
| `/usage` | 计费驾驶舱 | Y | - | - | Y | Y | Y |
| `/cost/records` | 调用明细 | Y | - | - | Y | Y | Y |

Menu-only narrowing: `/cost/quota-policies` menu shows for system/tenant admins only; `/dashboard` menu hidden for dept_manager. Landing pages (`roleHome`): auditor `/system/audit-operations`, security_officer `/security/alerts`, dept_manager `/cost/records`, others `/dashboard`.

## 4. Upgrade mapping (migration 890)

| Before | After | Notes |
|---|---|---|
| `platform_admin` | `platform_admin` | Unchanged; loses audit read (by design). |
| `admin` | `platform_admin` | users.role and permission_grants.role rewritten; one `role.migrated` audit row per user. |
| `auditor` (legacy, unused) | `auditor` | Now a real role with the audit duty. |
| - | `security_officer` | Registered as builtin system role; no account created. |

No auditor or security officer account is created automatically; after upgrade the system administrator creates them in user management. Break-glass: if no active `platform_admin` with a password remains, `user_admin` is restored to active `platform_admin` (audited); if that is impossible the migration raises a WARNING pointing to `BOOTSTRAP_ADMIN_PASSWORD`. Idempotent (tested).

Operator impact: after upgrade the system administrator can no longer open operation audit, content evidence, compliance overview or login history. Create an auditor account first if those are needed.

## 5. Out of scope / handoff

| Item | Owner | Note |
|---|---|---|
| `mcp_*` handlers, `agentguard_policy.go`, `policy_center_agent_behaviors.go`, `skill_assets.go` (`canManageAgentGuard`) still check `platform_admin` literally | W1 / W5 | Replace with `roles.CanManageSecurityPolicy` so the security officer can write. Until then the SoD guard allows the request and the handler refuses (403), i.e. fail-closed. |
| Other handlers with literal `platform_admin` checks (billing, CA certs, proxy, license, upgrade, users ...) | none needed | System duties; `admin` was migrated, so the literal check is correct. |
| BudgetSnapshot, PricesFx, SavingsBoard pages | W7 | Orphans kept. |
| Anomalies page | W8 | Orphan kept. |
| SecurityOperationsOverview copy pointing to the tool audit page | W8 | Entry now exists in the menu. |
| Terminology rollout (glossary section 1) | W6 / W8 | `docs/ui-glossary.md`. |
| Deleted orphans | W4 | RoutingDecisions, SecurityPolicy, Upgrade pages and their tests (no route or import referenced them). |

## Appendix: route class table

| Method | Route | Class |
|---|---|---|
| POST | `/admin/v1/logout` | `common` |
| GET | `/admin/v1/me` | `common` |
| POST | `/admin/v1/me/change-password` | `common` |
| GET | `/admin/v1/settings/org-labels` | `common` |
| PUT | `/admin/v1/settings/org-labels` | `system` |
| GET | `/admin/v1/tenants` | `system` |
| POST | `/admin/v1/tenants` | `system` |
| GET | `/admin/v1/tenants/{id}` | `system` |
| PATCH | `/admin/v1/tenants/{id}` | `system` |
| GET | `/admin/v1/tenants/{id}/teams` | `system` |
| GET | `/admin/v1/tenants/{id}/users` | `system` |
| GET | `/admin/v1/tenants/{id}/projects` | `system` |
| DELETE | `/admin/v1/tenants/{id}/projects/{projectId}` | `system` |
| GET | `/admin/v1/tenants/{id}/keys` | `system` |
| DELETE | `/admin/v1/tenants/{id}` | `system` |
| GET | `/admin/v1/projects` | `directory_read` |
| POST | `/admin/v1/projects` | `system` |
| GET | `/admin/v1/projects/{id}` | `system` |
| PATCH | `/admin/v1/projects/{id}` | `system` |
| DELETE | `/admin/v1/projects/{id}` | `system` |
| GET | `/admin/v1/projects/{id}/users` | `system` |
| POST | `/admin/v1/projects/{id}/users` | `system` |
| DELETE | `/admin/v1/projects/{id}/users/{userId}` | `system` |
| PATCH | `/admin/v1/projects/{id}/model-config` | `system` |
| GET | `/admin/v1/keys` | `directory_read` |
| POST | `/admin/v1/keys` | `system` |
| PATCH | `/admin/v1/keys/{id}` | `system` |
| POST | `/admin/v1/keys/{id}/revoke` | `system` |
| GET | `/admin/v1/keys/{id}/reveal` | `system` |
| DELETE | `/admin/v1/keys/{id}` | `system` |
| GET | `/admin/v1/providers` | `system` |
| GET | `/admin/v1/providers/metrics` | `system` |
| GET | `/admin/v1/providers/deleted` | `system` |
| POST | `/admin/v1/providers` | `system` |
| PATCH | `/admin/v1/providers/{id}` | `system` |
| GET | `/admin/v1/providers/{id}/credentials/history` | `system` |
| POST | `/admin/v1/providers/{id}/restore` | `system` |
| DELETE | `/admin/v1/providers/{id}` | `system` |
| GET | `/admin/v1/models` | `directory_read` |
| POST | `/admin/v1/models` | `system` |
| GET | `/admin/v1/models/eval-status` | `system` |
| POST | `/admin/v1/models/sync` | `system` |
| POST | `/admin/v1/models/sync/candidates` | `system` |
| POST | `/admin/v1/models/batch-delete` | `system` |
| POST | `/admin/v1/models/sync/preview` | `system` |
| POST | `/admin/v1/models/sync/verify` | `system` |
| POST | `/admin/v1/models/sync/commit` | `system` |
| DELETE | `/admin/v1/models/{id}` | `system` |
| PATCH | `/admin/v1/models/{id}/routing` | `system` |
| PATCH | `/admin/v1/models/{id}/status` | `system` |
| PATCH | `/admin/v1/models/{id}/proxy-config` | `system` |
| PATCH | `/admin/v1/models/{id}/capabilities` | `system` |
| GET | `/admin/v1/policies/model` | `system` |
| PUT | `/admin/v1/policies/model` | `system` |
| GET | `/admin/v1/group-mapping-rules` | `system` |
| POST | `/admin/v1/group-mapping-rules` | `system` |
| PATCH | `/admin/v1/group-mapping-rules/{id}` | `system` |
| DELETE | `/admin/v1/group-mapping-rules/{id}` | `system` |
| GET | `/admin/v1/identity/sources` | `system` |
| PUT | `/admin/v1/identity/sources/draft` | `system` |
| GET | `/admin/v1/directory/sources/draft` | `system` |
| PUT | `/admin/v1/directory/sources/draft` | `system` |
| POST | `/admin/v1/directory/sources/test` | `system` |
| POST | `/admin/v1/directory/sources/activate` | `system` |
| POST | `/admin/v1/directory/sources/disable` | `system` |
| POST | `/admin/v1/directory/sources/preview` | `system` |
| GET | `/admin/v1/directory/sources/previews/{id}` | `system` |
| POST | `/admin/v1/directory/sources/previews/{id}/activate` | `system` |
| GET | `/admin/v1/directory/sync-runs` | `system` |
| GET | `/admin/v1/directory/sync-runs/{id}` | `system` |
| POST | `/admin/v1/identity/sources/test` | `system` |
| POST | `/admin/v1/identity/sources/activate` | `system` |
| POST | `/admin/v1/identity/sources/disable` | `system` |
| POST | `/admin/v1/identity/sources/reconcile` | `system` |
| POST | `/admin/v1/identity/sources/adopt-runtime` | `system` |
| GET | `/admin/v1/identity/dept-mappings` | `system` |
| POST | `/admin/v1/identity/dept-mappings` | `system` |
| PATCH | `/admin/v1/identity/dept-mappings/{id}` | `system` |
| DELETE | `/admin/v1/identity/dept-mappings/{id}` | `system` |
| GET | `/admin/v1/identity/department-mappings` | `system` |
| POST | `/admin/v1/identity/department-mappings` | `system` |
| PATCH | `/admin/v1/identity/department-mappings/{id}` | `system` |
| DELETE | `/admin/v1/identity/department-mappings/{id}` | `system` |
| POST | `/admin/v1/identity/department-mappings/preview` | `system` |
| GET | `/admin/v1/identity/status` | `system` |
| GET | `/admin/v1/identity/overview` | `system` |
| GET | `/admin/v1/policies/quota` | `system` |
| PUT | `/admin/v1/policies/quota` | `system` |
| GET | `/admin/v1/rule-sets` | `security_config_read` |
| POST | `/admin/v1/rule-sets` | `security_write` |
| POST | `/admin/v1/rule-sets/{id}/publish` | `security_write` |
| POST | `/admin/v1/security/test` | `security_write` |
| POST | `/admin/v1/security/semantic/test-judge` | `security_write` |
| GET | `/admin/v1/security/semantic/settings` | `security_config_read` |
| PUT | `/admin/v1/security/semantic/settings` | `security_write` |
| GET | `/admin/v1/security/smart-detection/overview` | `security_record_read` |
| PUT | `/admin/v1/security/smart-detection/config` | `security_write` |
| GET | `/admin/v1/content-security/rules` | `security_config_read` |
| POST | `/admin/v1/content-security/rules` | `security_write` |
| GET | `/admin/v1/content-security/exceptions` | `security_config_read` |
| POST | `/admin/v1/content-security/exceptions` | `security_write` |
| DELETE | `/admin/v1/content-security/exceptions/{id}` | `security_write` |
| GET | `/admin/v1/content-security/file-policy` | `security_config_read` |
| PUT | `/admin/v1/content-security/file-policy` | `security_write` |
| GET | `/admin/v1/content-security/industry` | `security_config_read` |
| PUT | `/admin/v1/content-security/industry` | `security_write` |
| GET | `/admin/v1/security/policies` | `security_config_read` |
| POST | `/admin/v1/security/policies` | `security_write` |
| GET | `/admin/v1/security/policies/capabilities` | `security_config_read` |
| POST | `/admin/v1/security/policies/preview` | `security_config_read` |
| POST | `/admin/v1/security/policies/quick-create/generate` | `security_write` |
| POST | `/admin/v1/security/policies/quick-create/preview` | `security_config_read` |
| POST | `/admin/v1/security/policies/batch` | `security_write` |
| PATCH | `/admin/v1/security/policies/{id}` | `security_write` |
| GET | `/admin/v1/security/policy-assets` | `security_config_read` |
| PUT | `/admin/v1/security/policy-assets/{id}` | `security_write` |
| GET | `/admin/v1/rules` | `security_config_read` |
| POST | `/admin/v1/rules` | `security_write` |
| PATCH | `/admin/v1/rules/{id}` | `security_write` |
| DELETE | `/admin/v1/rules/{id}` | `security_write` |
| POST | `/admin/v1/rules/{id}/toggle` | `security_write` |
| POST | `/admin/v1/detectors/batch-update` | `security_write` |
| POST | `/admin/v1/detectors/init` | `security_write` |
| GET | `/admin/v1/audit/requests` | `evidence` |
| GET | `/admin/v1/audit/requests/{request_id}` | `evidence` |
| GET | `/admin/v1/audit/events` | `security_record_read` |
| GET | `/admin/v1/security/block-records` | `security_record_read` |
| GET | `/admin/v1/security/block-records/{block_id}` | `security_record_read` |
| GET | `/admin/v1/security/alert-occurrences` | `security_record_read` |
| GET | `/admin/v1/security/alert-occurrences/summary` | `security_record_read` |
| GET | `/admin/v1/security/alert-occurrences/operational` | `security_record_read` |
| GET | `/admin/v1/security/alert-occurrences/operational/summary` | `security_record_read` |
| GET | `/admin/v1/audit/dispositions` | `evidence` |
| PUT | `/admin/v1/audit/dispositions` | `alert_handle` |
| GET | `/admin/v1/audit/export` | `audit_export` |
| GET | `/admin/v1/audit/content` | `security_record_read` |
| GET | `/admin/v1/audit/content/security-overview` | `security_record_read` |
| GET | `/admin/v1/audit/content/users` | `security_record_read` |
| GET | `/admin/v1/audit/content/{session_id}` | `evidence` |
| GET | `/admin/v1/audit/content/{session_id}/events` | `evidence` |
| GET | `/admin/v1/audit/content/{session_id}/export` | `audit_export` |
| GET | `/admin/v1/usage/summary` | `system` |
| GET | `/admin/v1/usage/by-project` | `system` |
| GET | `/admin/v1/usage/cost-coverage` | `system` |
| GET | `/admin/v1/usage/by-model` | `system` |
| GET | `/admin/v1/usage/trend` | `system` |
| GET | `/admin/v1/usage/by-user` | `system` |
| GET | `/admin/v1/usage/by-key` | `system` |
| GET | `/admin/v1/usage/by-provider` | `system` |
| GET | `/admin/v1/usage/records` | `system` |
| GET | `/admin/v1/usage/records/summary` | `system` |
| GET | `/admin/v1/usage/recommendations` | `system` |
| GET | `/admin/v1/billing/analytics/summary` | `system` |
| GET | `/admin/v1/billing/analytics/breakdown` | `system` |
| GET | `/admin/v1/billing/analytics/series` | `system` |
| GET | `/admin/v1/billing/analytics/time-profile` | `system` |
| GET | `/admin/v1/billing/analytics/department-provider-matrix` | `system` |
| GET | `/admin/v1/billing/analytics/report` | `system` |
| GET | `/admin/v1/system/initialization` | `common` |
| POST | `/admin/v1/system/initialization/retry` | `system` |
| GET | `/admin/v1/users/{user_id}/usage/summary` | `system` |
| GET | `/admin/v1/users/{user_id}/usage/trend` | `system` |
| GET | `/admin/v1/users/{user_id}/usage/by-model` | `system` |
| GET | `/admin/v1/users/{user_id}/usage/records` | `system` |
| GET | `/admin/v1/agent-identities` | `system` |
| POST | `/admin/v1/agent-identities` | `system` |
| GET | `/admin/v1/agent-sessions` | `security_record_read` |
| GET | `/admin/v1/agent-sessions/stats` | `security_record_read` |
| GET | `/admin/v1/agent-sessions/distribution` | `security_record_read` |
| GET | `/admin/v1/agent-sessions/by-type` | `security_record_read` |
| GET | `/admin/v1/agent-sessions/{session_id}` | `security_record_read` |
| GET | `/admin/v1/stats/overview` | `system` |
| GET | `/admin/v1/stats/org` | `system` |
| GET | `/admin/v1/stats/users` | `system` |
| GET | `/admin/v1/stats/apps` | `system` |
| GET | `/admin/v1/stats/models` | `system` |
| GET | `/admin/v1/stats/agents` | `system` |
| GET | `/admin/v1/stats/agents/distribution` | `system` |
| GET | `/admin/v1/audit/agents/user/{user_id}` | `security_record_read` |
| GET | `/admin/v1/audit/agents/sessions` | `security_record_read` |
| GET | `/admin/v1/audit/tools/stats` | `security_record_read` |
| GET | `/admin/v1/audit/tools/high-risk` | `security_record_read` |
| GET | `/admin/v1/audit/tools/session/{session_id}` | `security_record_read` |
| GET | `/admin/v1/audit/tools/user/{user_id}` | `security_record_read` |
| GET | `/admin/v1/audit/tools/trend` | `security_record_read` |
| GET | `/admin/v1/tools/config` | `security_config_read` |
| POST | `/admin/v1/tools/config` | `security_write` |
| PUT | `/admin/v1/tools/config/{id}` | `security_write` |
| DELETE | `/admin/v1/tools/config/{id}` | `security_write` |
| POST | `/admin/v1/tools/config/batch` | `security_write` |
| GET | `/admin/v1/skills/assets` | `security_config_read` |
| GET | `/admin/v1/skills/assets/{id}/versions` | `security_config_read` |
| GET | `/admin/v1/skills/invocations` | `security_record_read` |
| POST | `/admin/v1/skills/scan` | `security_write` |
| POST | `/admin/v1/skills/versions/{id}/admission` | `security_write` |
| GET | `/admin/v1/agentguard/policies` | `security_config_read` |
| POST | `/admin/v1/agentguard/policies` | `security_write` |
| PUT | `/admin/v1/agentguard/policies/{id}` | `security_write` |
| GET | `/admin/v1/agentguard/templates` | `security_config_read` |
| GET | `/admin/v1/agentguard/governance/stats` | `security_record_read` |
| GET | `/admin/v1/agentguard/risk-overview` | `security_record_read` |
| POST | `/admin/v1/agentguard/policies/simulate` | `security_config_read` |
| GET | `/admin/v1/agentguard/policies/{id}/versions` | `security_config_read` |
| POST | `/admin/v1/agentguard/policies/{id}/rollback` | `security_write` |
| GET | `/admin/v1/agentguard/exceptions` | `security_config_read` |
| POST | `/admin/v1/agentguard/exceptions` | `security_write` |
| DELETE | `/admin/v1/agentguard/exceptions/{id}` | `security_write` |
| POST | `/admin/v1/agentguard/exceptions/suggest` | `security_config_read` |
| GET | `/admin/v1/agentguard/confirmations` | `security_record_read` |
| POST | `/admin/v1/agentguard/confirmations/{id}/resolve` | `security_write` |
| GET | `/admin/v1/agentguard/behavior/baseline` | `security_config_read` |
| GET | `/admin/v1/agentguard/rollouts` | `security_config_read` |
| POST | `/admin/v1/agentguard/rollouts` | `security_write` |
| GET | `/admin/v1/policy-center/agent-behaviors` | `security_config_read` |
| PUT | `/admin/v1/policy-center/agent-behaviors/{key}` | `security_write` |
| GET | `/admin/v1/proxy/forward-access` | `evidence` |
| GET | `/admin/v1/audit/access-retention` | `evidence` |
| GET | `/admin/v1/audit/access-retention/runs` | `evidence` |
| GET | `/admin/v1/audit/access-retention/{request_id}/timeline` | `evidence` |
| POST | `/admin/v1/audit/access-retention/{request_id}/timeline` | `evidence` |
| GET | `/admin/v1/audit/access-retention/export` | `audit_export` |
| GET | `/admin/v1/audit/access-retention/{request_id}/content` | `evidence` |
| POST | `/admin/v1/audit/access-retention/{request_id}/content` | `evidence` |
| GET | `/admin/v1/audit/access-retention/{request_id}/image-proxy` | `evidence` |
| GET | `/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview` | `evidence` |
| GET | `/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original` | `evidence` |
| GET | `/admin/v1/audit/access-retention/{request_id}/blob` | `evidence` |
| GET | `/admin/v1/llm-provider-catalog` | `common` |
| POST | `/admin/v1/llm-provider-catalog/test-match` | `system` |
| GET | `/admin/v1/proxy/whitelist` | `system` |
| POST | `/admin/v1/proxy/whitelist` | `system` |
| PUT | `/admin/v1/proxy/whitelist/{id}` | `system` |
| DELETE | `/admin/v1/proxy/whitelist/{id}` | `system` |
| GET | `/admin/v1/reverse-proxy/routes` | `system` |
| POST | `/admin/v1/reverse-proxy/routes` | `system` |
| PUT | `/admin/v1/reverse-proxy/routes/{id}` | `system` |
| DELETE | `/admin/v1/reverse-proxy/routes/{id}` | `system` |
| POST | `/admin/v1/ca/generate` | `system` |
| GET | `/admin/v1/ca/certificate` | `system` |
| GET | `/admin/v1/ca/download` | `system` |
| GET | `/admin/v1/ca/{id}/download` | `system` |
| GET | `/admin/v1/ca/list` | `system` |
| POST | `/admin/v1/ca/{id}/activate` | `system` |
| DELETE | `/admin/v1/ca/{id}` | `system` |
| GET | `/admin/v1/retention/storage-config` | `system` |
| PUT | `/admin/v1/retention/storage-config` | `system` |
| POST | `/admin/v1/retention/storage-config/test` | `system` |
| GET | `/admin/v1/users` | `system` |
| POST | `/admin/v1/users` | `system` |
| PATCH | `/admin/v1/users/{id}` | `system` |
| DELETE | `/admin/v1/users/{id}` | `system` |
| POST | `/admin/v1/users/{id}/reset-password` | `system` |
| PATCH | `/admin/v1/users/{id}/status` | `system` |
| POST | `/admin/v1/users/{id}/department/automatic` | `system` |
| GET | `/admin/v1/users/{id}/grants` | `system` |
| GET | `/admin/v1/users/{id}/keys` | `system` |
| POST | `/admin/v1/users/{id}/grants` | `system` |
| DELETE | `/admin/v1/users/{id}/grants/{grant_id}` | `system` |
| GET | `/admin/v1/users/{id}/login-history` | `login_history` |
| GET | `/admin/v1/users/{id}/detail` | `system` |
| GET | `/admin/v1/system/settings` | `common` |
| PUT | `/admin/v1/system/settings` | `system` |
| GET | `/admin/v1/security/reply-policy` | `security_config_read` |
| PUT | `/admin/v1/security/reply-policy` | `security_write` |
| GET | `/admin/v1/security/semantic/runtime-status` | `security_config_read` |
| POST | `/admin/v1/system/lse/test` | `system` |
| GET | `/admin/v1/system/license` | `common` |
| POST | `/admin/v1/system/license/import` | `system` |
| GET | `/admin/v1/system/license/host-info` | `system` |
| GET | `/admin/v1/system/audit-operations` | `audit` |
| GET | `/admin/v1/system/version` | `common` |
| POST | `/admin/v1/system/upgrade/check` | `system` |
| POST | `/admin/v1/system/upgrade/upload` | `system` |
| POST | `/admin/v1/system/upgrade/execute` | `system` |
| POST | `/admin/v1/system/upgrade/rollback` | `system` |
| GET | `/admin/v1/system/upgrade/history` | `system` |
| POST | `/admin/v1/system/ruleset/sync` | `system` |
| POST | `/admin/v1/teams` | `system` |
| GET | `/admin/v1/teams` | `directory_read` |
| DELETE | `/admin/v1/teams/{id}` | `system` |
| POST | `/admin/v1/teams/{id}/members` | `system` |
| DELETE | `/admin/v1/teams/{id}/members/{user_id}` | `system` |
| GET | `/admin/v1/teams/{id}/members` | `system` |
| POST | `/admin/v1/teams/{id}/members/batch` | `system` |
| PUT | `/admin/v1/teams/{id}/budget` | `system` |
| GET | `/admin/v1/teams/{id}/models` | `system` |
| PUT | `/admin/v1/teams/{id}/models` | `system` |
| DELETE | `/admin/v1/teams/{id}/models/{model_id}` | `system` |
| GET | `/admin/v1/teams/{id}/effective` | `system` |
| GET | `/admin/v1/teams/{id}/projects` | `system` |
| GET | `/admin/v1/teams/{id}/usage` | `system` |
| PATCH | `/admin/v1/projects/{id}/team` | `system` |
| PATCH | `/admin/v1/users/{id}/personal-budget` | `system` |
| GET | `/admin/v1/budgets/snapshot` | `system` |
| POST | `/admin/v1/budgets/keys/{key_prefix}/pause` | `system` |
| POST | `/admin/v1/budgets/keys/{key_prefix}/unpause` | `system` |
| GET | `/admin/v1/budgets/pause-log` | `system` |
| GET | `/admin/v1/billing/runtime` | `system` |
| GET | `/admin/v1/billing/customers` | `system` |
| GET | `/admin/v1/billing/models` | `system` |
| PUT | `/admin/v1/billing/customers/{id}/group` | `system` |
| GET | `/admin/v1/billing/customer-groups` | `system` |
| POST | `/admin/v1/billing/customer-groups` | `system` |
| PATCH | `/admin/v1/billing/customer-groups/{id}` | `system` |
| POST | `/admin/v1/billing/wallets/credit` | `system` |
| POST | `/admin/v1/billing/wallets/adjustments` | `system` |
| GET | `/admin/v1/billing/ledger` | `system` |
| GET | `/admin/v1/billing/prices` | `system` |
| POST | `/admin/v1/billing/prices` | `system` |
| POST | `/admin/v1/billing/prices/newapi-ratio` | `system` |
| GET | `/admin/v1/billing/channel-fixed-costs` | `system` |
| PUT | `/admin/v1/billing/channel-fixed-costs` | `system` |
| DELETE | `/admin/v1/billing/channel-fixed-costs` | `system` |
| DELETE | `/admin/v1/billing/upstream-rates` | `system` |
| GET | `/admin/v1/billing/tariffs` | `system` |
| POST | `/admin/v1/billing/tariffs` | `system` |
| DELETE | `/admin/v1/billing/tariffs/{id}` | `system` |
| POST | `/admin/v1/billing/tariffs/{id}/publish` | `system` |
| POST | `/admin/v1/billing/tariffs/{id}/retire` | `system` |
| GET | `/admin/v1/billing/tariffs/preview` | `system` |
| GET | `/admin/v1/billing/redemptions` | `system` |
| POST | `/admin/v1/billing/redemptions` | `system` |
| PATCH | `/admin/v1/billing/redemptions/{id}` | `system` |
| GET | `/admin/v1/rules/pull-status` | `security_config_read` |
| GET | `/admin/v1/fx/current` | `system` |
| PUT | `/admin/v1/fx` | `system` |
| GET | `/admin/v1/fx/history` | `system` |
| GET | `/admin/v1/savings/summary` | `system` |
| GET | `/admin/v1/savings/trend` | `system` |
| GET | `/admin/v1/savings/config` | `system` |
| PUT | `/admin/v1/savings/config` | `system` |
| GET | `/admin/v1/agent-operation-protection` | `security_config_read` |
| PUT | `/admin/v1/agent-operation-protection` | `security_write` |
| GET | `/admin/v1/agent-operation-events` | `security_record_read` |
| GET | `/admin/v1/agent-operation-events/{public_event_id}` | `security_record_read` |
| GET | `/admin/v1/alerts/inbox` | `common` |
| POST | `/admin/v1/alerts/{id}/read` | `common` |
| GET | `/admin/v1/alert-groups` | `security_record_read` |
| GET | `/admin/v1/alert-groups/{id}` | `security_record_read` |
| GET | `/admin/v1/alert-groups/{id}/events` | `security_record_read` |
| PATCH | `/admin/v1/alert-groups/{id}` | `alert_handle` |
| GET | `/admin/v1/notify-channels` | `system` |
| POST | `/admin/v1/notify-channels` | `system` |
| PUT | `/admin/v1/notify-channels/{id}` | `system` |
| DELETE | `/admin/v1/notify-channels/{id}` | `system` |
| POST | `/admin/v1/notify-channels/{id}/test` | `system` |
| GET | `/admin/v1/proxy-access-keys` | `system` |
| POST | `/admin/v1/proxy-access-keys` | `system` |
| PUT | `/admin/v1/proxy-access-keys/{id}` | `system` |
| DELETE | `/admin/v1/proxy-access-keys/{id}` | `system` |
| POST | `/admin/v1/proxy-access-keys/{id}/rotate` | `system` |
| GET | `/admin/v1/mcp-servers` | `security_config_read` |
| POST | `/admin/v1/mcp-servers` | `system` |
| PUT | `/admin/v1/mcp-servers/{id}` | `system` |
| DELETE | `/admin/v1/mcp-servers/{id}` | `system` |
| POST | `/admin/v1/mcp-servers/{id}/sync` | `system` |
| POST | `/admin/v1/mcp-servers/{id}/test-connection` | `system` |
| GET | `/admin/v1/mcp-servers/{id}/tools` | `security_config_read` |
| POST | `/admin/v1/mcp-servers/{id}/admission` | `security_write` |
| POST | `/admin/v1/mcp-tools/{id}/admission` | `security_write` |
| GET | `/admin/v1/mcp-tools/shadow-check` | `security_config_read` |
| GET | `/admin/v1/mcp-policies` | `security_config_read` |
| POST | `/admin/v1/mcp-policies` | `security_write` |
| POST | `/admin/v1/mcp-policies/simulate` | `security_config_read` |
| GET | `/admin/v1/mcp-policies/shadow-check` | `security_config_read` |
| POST | `/admin/v1/mcp-policies/shadow-check` | `security_config_read` |
| PUT | `/admin/v1/mcp-policies/{id}` | `security_write` |
| DELETE | `/admin/v1/mcp-policies/{id}` | `security_write` |
| GET | `/admin/v1/provider-price-snapshots` | `system` |
| POST | `/admin/v1/audit-chain/verify` | `audit` |
| GET | `/admin/v1/audit-chain/stats` | `audit` |
| GET | `/admin/v1/audit-chain/export` | `audit_export` |
| GET | `/admin/v1/anomalies` | `system` |
| POST | `/admin/v1/anomalies/{id}/ack` | `system` |
| POST | `/admin/v1/forecast/jobs` | `system` |
| GET | `/admin/v1/forecast/jobs` | `system` |
| GET | `/admin/v1/forecast/jobs/{id}` | `system` |
| GET | `/admin/v1/model-routing` | `system` |
| GET | `/admin/v1/model-routing/status` | `system` |
| GET | `/admin/v1/model-routing/routes` | `system` |
| GET | `/admin/v1/model-routing/models` | `system` |
| PUT | `/admin/v1/model-routing/default` | `system` |
| DELETE | `/admin/v1/model-routing/default` | `system` |
| POST | `/admin/v1/model-routing/validate` | `system` |
| PUT | `/admin/v1/model-routing/models/{model_name}` | `system` |
| DELETE | `/admin/v1/model-routing/models/{model_name}` | `system` |
| PUT | `/admin/v1/model-routing/models/*` | `system` |
| DELETE | `/admin/v1/model-routing/models/*` | `system` |
| GET | `/admin/v1/routing-policies` | `system` |
| PUT | `/admin/v1/routing-policies` | `system` |
| DELETE | `/admin/v1/routing-policies/{id}` | `system` |
| POST | `/admin/v1/routing-policies/test` | `system` |
| GET | `/admin/v1/routing-decisions` | `system` |
| GET | `/admin/v1/routing-decisions/{request_id}` | `system` |
| GET | `/admin/v1/roles` | `common` |
| GET | `/admin/v1/roles/{name}/permissions` | `common` |
| GET | `/admin/v1/permissions/resources` | `common` |
| GET | `/admin/v1/permissions/actions` | `common` |
| GET | `/admin/v1/me/permissions` | `common` |
| GET | `/admin/v1/audit/login-history` | `login_history` |
