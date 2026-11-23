-- +goose Up
-- +goose StatementBegin

-- 修复 request_logs 表缺少的审计字段
-- 这些字段在 gateway-core 的 FinalizeRequestLog 中被写入，但 schema 中不存在

-- 添加 input_audit_result 字段，存储输入安全检测结果
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS input_audit_result JSONB DEFAULT NULL;

-- 添加 output_audit_result 字段，存储输出安全检测结果
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS output_audit_result JSONB DEFAULT NULL;

-- 添加索引以支持审计 action 查询。不要对整段 jsonb 建 btree 索引：
-- findings/evidence 可能很长且不可压缩，会导致 "index row size exceeds btree maximum"
-- 并让 request_logs 写入失败。
CREATE INDEX IF NOT EXISTS idx_request_logs_input_audit
    ON request_logs ((input_audit_result->>'action_taken'))
    WHERE input_audit_result IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_request_logs_output_audit
    ON request_logs ((output_audit_result->>'action_taken'))
    WHERE output_audit_result IS NOT NULL;
