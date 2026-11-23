# 智能体算力安全网关 · Agent Compute Security Gateway

> JJDGuard 企业级大模型与智能体安全网关。

统一接入公网大模型，隐藏并管控上游凭证，对模型请求、Agent 工具调用与代理出口流量做安全检测、治理和审计，并沉淀可复盘的安全证据。

## 特性

- **统一接入与凭证托管**：聚合 OpenAI、Anthropic 等上游供应商，对外仅暴露统一 API Key，上游真实凭证加密存储、不下发。
- **双模代理**：反向代理（API Key 鉴权转发，主链路）+ 正向代理（企业出网到公网大模型），出口侧带 SSRF 防护（DNS 解析、IP pinning、CIDR 拦截）。
- **Agent 归因与工具治理**：识别请求中的 Agent、工具、动作、目标、数据与策略版本；工具调用支持 allow / audit / confirm / block 四级决策。
- **多级运行模式**：observe / audit / strict，可先影子观察再逐步执行，降低上线误报风险。
- **检测与 DLP**：参数级污染追踪、目标归一化、命令治理（no-shell / argv 白名单）、SQL 治理、高置信 DLP（私钥 / JWT / API Key / PII，证据脱敏）、行为窗口异常检测。
- **访问留存与审计**：按流量方向（反向 / 正向 / 经过设备）留存访问记录，支持 CSV / JSON 导出；策略闭环覆盖策略、例外、版本、回滚、确认任务与操作审计。
- **多租户与 RBAC**：租户隔离、子账号权限分级，平台级 / 单位级菜单与能力按角色收敛。
- **私有化部署**：Docker Compose 一键部署，支持离线交付包。

## 架构

本项目是一个 monorepo：Go 多模块工作区（`go.work`）+ React 控制台 + Python 检测服务。

| 服务 | 技术栈 | 默认端口 | 职责 |
|------|--------|----------|------|
| `apps/gateway-core` | Go | 8080 | 运行时网关、反向代理主链路：API Key 鉴权 + Redis 限流、模型 → 供应商路由、provider 适配、调用检测引擎、请求审计 |
| `apps/control-plane` | Go | 8081 | 控制面 Admin API：模型 / 供应商 / 策略 / 规则 CRUD、用户 / 租户 / RBAC、审计查询与访问留存导出 |
| `apps/security-engine` | Python · FastAPI | 8000 | 安全检测服务：PII / 注入 / 泄露 / 内容安全 detectors，`check_input` / `check_output`，返回 findings 与处置动作 |
| `apps/proxy-server` | Go | 3128 | 出口正向代理：企业出网到公网大模型，SSRF 防护 |
| `apps/web-console` | React 18 · TypeScript · Vite · Ant Design | 3000 | 管理控制台前端 |
| `apps/worker` | Go | — | 后台异步任务（建设中） |
| `packages/shared-go` | Go | — | Go 共享库 |

数据层：PostgreSQL 16 + Redis 7。

请求主链路（反向代理）：

```text
客户端 → gateway-core ──┬─ auth（API Key 校验 + 限流）
                        ├─ modelrouter（模型 → 供应商路由）
                        ├─ security-engine（输入 / 输出检测）
                        └─ audit（请求留存）
                        → proxy-server → 公网大模型供应商
```

## 快速开始

### 环境要求

- Docker / Docker Compose（部署）
- 本地开发额外需要：Go >= 1.25、Node.js >= 20、Python >= 3.11

### 一键部署（Docker Compose）

```bash
cd deploy/docker-compose
sh deploy-oneclick.sh
```

脚本会自动生成 `.env`、挑选可用端口、生成上游凭证加密密钥与初始管理员密码，启动全栈、执行私有化迁移、初始化运行时默认值并跑冒烟测试，最后打印访问地址与管理员密码（同时写入 `deploy/docker-compose/.deploy-result`）。

> 首次登录后请立即修改初始管理员密码。

离线交付包与升级流程见 [私有化部署指南](deploy/docker-compose/README.md)。

## 本地开发

常用命令如下。

### 后端（Go 模块，以 control-plane 为例）

```bash
cd apps/control-plane
GOWORK=off go build ./...   # 构建
GOWORK=off go test ./...    # 测试
GOWORK=off go vet ./...     # 静态检查
```

`gateway-core`、`proxy-server`、`packages/shared-go` 同理替换目录。

### 检测服务（Python · security-engine）

```bash
cd apps/security-engine
python3 -m pytest          # 测试
python3 -m compileall app  # 构建检查
```

### 前端控制台（web-console）

```bash
cd apps/web-console
npm install
npm run dev      # 开发服务器
npm run build    # 构建
npm run test     # 测试
npm run lint     # lint
```

## 安全敏感区

改动以下区域必须附带测试与自查：

- 鉴权 / 多租户隔离 / 子账号权限（越权风险最高）
- 上游模型供应商凭证的存储与转发
- 计费 / 配额相关路径
- 正向 / 反向代理、回调与上游地址处理（SSRF 风险）

## 能力边界

本网关是 LLM / 智能体流量侧的安全治理与审计层，定位明确：

- 不替代终端 EDR、主机防病毒、数据库最小权限与云安全基线；
- 一期检测聚焦高置信密钥 / PII 与可解释规则，不承诺识别所有业务敏感数据；
- 生产前建议先在 observe / audit 影子模式校准误报，再切换到拦截；
- 并发容量以实际压测结论为准，未压测场景不外推容量承诺。

## 文档

- [私有化部署指南](deploy/docker-compose/README.md)
- [docs/](docs/) — 计费与脱敏、容量、门户集成等说明
- [CHANGELOG.md](CHANGELOG.md) — 版本记录

## 许可

本项目以 [GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0）开源。基于本项目修改并通过网络对外提供服务时，须按 AGPL-3.0 向服务使用者提供对应源码。

随附的第三方组件与模型各自的许可见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
