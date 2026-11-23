# UI glossary (W4 4.8)

Authoritative display terms for the web console. W6/W8 align their pages to this table; new UI copy must use these terms. Every Chinese term below was taken from existing source (Layout.tsx, roles.ts, plan) and is not a new coinage.

## 1. Enforcement verb: one word

The console used three verbs for the same outcome (request stopped by policy). Occurrences counted over the baseline 3b8a624d snapshot (web-console + control-plane sources, migrations, remediation plan):

| Term | Occurrences | Decision |
|---|---|---|
| 阻断 | 336 | **Canonical.** Already the menu label (阻断记录). |
| 拒绝 | 147 | Keep only for *approval workflows* (an approver says no), never for policy enforcement. |
| 拦截 | 73 | Retire. Replace with 阻断. |

Rules:

- Policy stopped the request (action `block` / `deny`): display 已阻断. Do not display 已拦截.
- Record mode (observe only, nothing stopped): must not display 已阻断; show the actual `action_taken` (see plan item 8.8, owned by W8).
- Approval declined (MCP approvals, exceptions): 拒绝.

## 2. Menu groups (five drawers)

| Key | Label | Holds |
|---|---|---|
| `group-overview` | 总览 | 态势总览, 消息中心 |
| `group-secops` | 安全运营 | 安全护栏, MCP 安全网关 |
| `group-audit` | 审计合规 | 合规总览, 操作审计, 内容留证, 登录历史 |
| `group-resource` | 资源与计费 | 模型管控, 计费治理 |
| `group-system` | 系统管理 | 身份与访问, 安全互联, platform settings |

## 3. Disambiguated names

| Was | Now | Why |
|---|---|---|
| 安全运营总览 (under audit) | 合规总览 | Two "overview" entries; the audit one is the compliance view. |
| 计费驾驶舱 vs 计费统计 | 计费驾驶舱 | Single name for `/usage`. 计费统计 is retired. |
| 内容留证 vs 内容留存存储 | unchanged, different drawers | 内容留证 = evidence (审计合规); 内容留存存储 = storage backend config (系统管理). |
| 消息中心 in 系统管理 | moved to 总览 | It is an inbox, not configuration. |

## 4. Role names

| Code | Label |
|---|---|
| `platform_admin` | 系统管理员 |
| `admin` (legacy, migrated by 890) | 管理员（历史） |
| `security_officer` | 安全保密管理员 |
| `auditor` | 审计员 |
| `tenant_owner` | 单位管理员 |
| `dept_manager` | 部门主管（只读） |
