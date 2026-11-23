-- 094: usage_rollup_hourly 增加"是否大模型流量"分类计数
-- 用途: 态势总览 + 按密钥/用户/模型/应用统计的"请求数"只统计大模型相关流量,
--       即正向代理的 llm/ai_ide + 反向代理的 API 调用(endpoint_type<>'proxy'),
--       排除正向代理的普通网页(normal_public)与设备(device)流量。
-- ai_success_count: 上述大模型请求里 request_status='success' 的条数(供应用成功率口径一致)。
-- 不变式: ai_request_count + non_ai_request_count == request_count
-- 注意: 加列后历史桶默认为 0,需对存量做一次性回填(从 request_logs 重算)。
ALTER TABLE usage_rollup_hourly
  ADD COLUMN IF NOT EXISTS ai_request_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS non_ai_request_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ai_success_count integer NOT NULL DEFAULT 0;
