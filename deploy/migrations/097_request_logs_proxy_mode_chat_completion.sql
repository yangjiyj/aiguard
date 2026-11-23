-- 097_request_logs_proxy_mode_chat_completion.sql
-- 修正 proxy_mode 列默认值与业务语义的偏离。
--
-- 历史背景：
--   007 引入 proxy_mode 时默认值写成 'reverse'，但正向 chat completions
--   路径（gateway-core/internal/handler/interfaces.go 的 EnsureRequestLog
--   三处 INSERT）没有显式写该列，导致所有客户端经网关做模型中转的请求
--   都被错记为反向代理。前端 AccessRetention / UnifiedAlerts 把
--   proxy_mode 直接映射成中文标签，UI 上 Claude Code / OpenCode 的请求
--   被误标成「反向代理 / 其他工具调用」，对客户无法解释。
--
-- 三态语义（覆盖产品所有出入站模式）：
--   - forward         正向 HTTP/HTTPS 代理：员工经网关访问外部 AI 网站
--                     （豆包/DeepSeek/元宝网页等），proxy_target_host 非空
--   - chat_completion 模型中转：客户端用网关 API Key 调
--                     /v1/chat/completions / /v1/messages，网关做鉴权、
--                     路由、计费、审计后转给上游模型 provider
--   - reverse         反向代理：企业内部模型服务（如本地 llama-server）
--                     通过 reverse_proxy_routes 对外暴露
--
-- 改动：
--   1) 列默认值改为 'chat_completion'（新代码路径仍要显式写）
--   2) 回填历史数据：proxy_target_host 为空且 model_id 非空的 'reverse'
--      行改判为 'chat_completion'
--   3) 更新列注释，写清三态
--
-- 幂等：每条语句都可用 WHERE 与 IS DISTINCT FROM 安全重复执行。

ALTER TABLE request_logs
    ALTER COLUMN proxy_mode SET DEFAULT 'chat_completion';

COMMENT ON COLUMN request_logs.proxy_mode IS
    '代理模式: forward(正向代理,员工出海) / chat_completion(模型中转,/v1/chat/completions) / reverse(反向代理,企业内部模型对外)';

-- Historical rows are handled by request_log_compatibility_v1 after migration
-- 835. This expand step remains independent of request_logs cardinality.
