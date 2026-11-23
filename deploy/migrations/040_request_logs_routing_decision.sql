-- 040_request_logs_routing_decision.sql
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS routing_decision_json JSONB;
COMMENT ON COLUMN request_logs.routing_decision_json IS '路由决策因子（白盒可解释）：model_layer/governor_override/provider_layer/fallback_retries';
