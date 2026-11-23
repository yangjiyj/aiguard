# Goal Contract: Gateway Hot Path Split

## Loop ID

20260618-gateway-hot-path-split

## Owner

产品/工程负责人：yj

## 目标

拆分 `apps/gateway-core/internal/handler/chat_completions.go` 中 `/v1/chat/completions` 的热路径职责，把请求解析、运行时上下文、策略/限流、路由决策、安全适配、审计发布和响应收口从单个大函数中拆成可测试组件。

本轮优先保护客户兼容性和网关热路径性能：客户 API 请求/响应结构不变，鉴权、额度、模型路由、同步安全阻断、供应商转发、fallback、审计和用量记录行为必须由回归测试证明保持一致。`messages` 和 `responses` 入口只允许做兼容性适配；如果拆分要求同时重构多个模型 API 入口，则触发停止条件。

## 为什么现在做

Loop 1 到 Loop 4 已把事件总线、留存、告警聚合和读模型从控制台高频路径拆出。当前最大耦合点回到网关运行时：`chat_completions.go` 同时承载鉴权、路由、安全、审计、响应处理和 fallback。继续把所有能力揉在同一条同步路径里，会在模型/租户/策略规模增长后拖慢热路径，并让任何安全或审计迭代都冒着破坏客户 API 的风险。

## 允许修改

- `apps/gateway-core/**`
- `packages/shared-go/**`
- `docs/harness/runs/**`
- `docs/superpowers/plans/**`

## 禁止修改

- `apps/control-plane/**`，除非目标契约要求新增接口适配
- `apps/web-console/**`
- `apps/security-engine/**`
- 现有客户 API 响应结构的不兼容变更
- 上游供应商凭证存储/密钥处理语义
- `go.work`

## 输入

- Playbook：`docs/harness/playbooks/05-gateway-hot-path-split.md`
- 架构设计：`docs/superpowers/specs/2026-06-18-agent-security-gateway-product-architecture-design.md`
- Loop 设计：`docs/superpowers/specs/2026-06-18-loop-harness-transformation-design.md`
- 主热路径：`apps/gateway-core/internal/handler/chat_completions.go`
- 共享 handler 依赖：`apps/gateway-core/internal/handler/interfaces.go`
- 共享 routing/governor：`apps/gateway-core/internal/handler/routing.go`、`apps/gateway-core/internal/handler/routing_integration.go`、`apps/gateway-core/internal/handler/governor_integration.go`
- 回归测试基线：`apps/gateway-core/internal/handler/chat_completions_test.go`、`apps/gateway-core/internal/handler/chat_completions_guardrail_failmode_test.go`、`apps/gateway-core/internal/handler/chat_completions_agentguard_test.go`

## 完成标准

- [x] 为当前 `/v1/chat/completions` 关键行为补回归测试，覆盖成功转发、安全 reply、provider fallback、上游错误和审计/用量收口。
- [x] 请求解析从主 handler 中抽出，非法 JSON、空 body、stream 参数等客户可见错误语义保持一致。
- [x] runtime context builder 独立可测，能构造 partial/full request envelope，并保留 tenant、project、user、key、team、model、provider、prompt tokens 和 LSE 字段。
- [x] 策略/限流/并发预检独立可测，model policy、quota、rate limit、concurrency release 行为保持一致。
- [x] routing decision 独立可测，provider override、fallback chain、routing headers 和 routing audit 事件保持一致。
- [x] security adapter 独立可测，tool risk、input security、output security 的 allow/block/reply/mask/fail-open/fail-close 行为保持一致。
- [x] audit publisher 与 response finalizer 独立可测，request log、content log、security event、proxy usage、SSE/JSON 响应收口不丢事件、不重复写。
- [x] `messages` 和 `responses` 入口继续通过现有测试；如需改动，必须限于兼容拆分接口。
- [x] `apps/gateway-core` 全量测试和构建通过。

## 验证命令

```bash
scripts/harness/preflight.sh --goal docs/harness/runs/20260618-gateway-hot-path-split-goal-contract.md
scripts/harness/scope-check.sh --goal docs/harness/runs/20260618-gateway-hot-path-split-goal-contract.md
cd apps/gateway-core && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./internal/handler -run "Chat|HotPath|RequestParser|RuntimeContext|Routing|Security|Finalizer" -count=1
cd apps/gateway-core && PATH=/usr/local/go/bin:$PATH GOWORK=off go test ./...
cd apps/gateway-core && PATH=/usr/local/go/bin:$PATH GOWORK=off go build -o /tmp/newapi-gateway-core ./cmd/server
git diff --check
git diff --cached --check
```

## 停止条件

- 拆分需要同时重构 `/v1/messages`、`/v1/responses` 等多个模型 API 入口。
- 任何客户可见 API 响应结构、错误码或 SSE 行为出现不兼容变化且无法解释为缺陷修复。
- 无法用自动化测试证明热路径行为保持一致。
- 拆分让同步热路径新增重型 IO、控制台查询、长事务或大对象留存写入。
- 发现鉴权/越权、密钥泄露、SSRF 或敏感日志风险，需要先修安全缺陷再继续结构拆分。

## 证据

- Evidence directory: `.harness/runs/20260618-gateway-hot-path-split`

## 决策

- Decision: `complete`
- Reason: Gateway Hot Path Split 已在不改变客户 API 的前提下完成 parser、runtime context、policy preflight、routing decision、security adapter 和 response finalizer 拆分，并通过热路径专项、gateway-core 全量测试、构建与推送门禁验证。

## 经验回灌

- 执行过程中追加每个拆分阶段的测试证据、兼容性结论和后续可迭代边界。
- 2026-06-18：已完成热路径回归测试与 request parser 拆分；`HotPath`、`RequestParser|HotPath`、`Chat|RequestParser|HotPath|Fallback|Guardrail|AgentGuard` 专项测试通过。
- 2026-06-18：已完成 runtime context builder 抽取；partial/full envelope 字段映射、routing prompt context 和 proxy identity 场景均有单测覆盖。
- 2026-06-18：已完成 policy preflight 抽取；model policy、quota/concurrency release、proxy identity switch 均有单测覆盖。
- 2026-06-18：已完成 routing decision 抽取；provider override、fallback chain 和 RoutingDecision 组装均有单测覆盖。
- 2026-06-18：已完成 security adapter 抽取；input reply/block 和 output mask 单测通过，既有 guardrail/AgentGuard 测试保持通过。
- 2026-06-18：已完成 JSON response finalizer 抽取；成功响应、上游 HTTP 错误和网络错误收口有单测覆盖，streaming 相关测试保持通过。
- 2026-06-18：最终验证通过：Harness preflight/scope-check、gateway-core `go test ./...`、handler 兼容专项、gateway server build、diff check 均通过。
