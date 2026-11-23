-- +goose Up
-- +goose StatementBegin

-- 为 rules 表添加 description 字段，用于安全规则说明
ALTER TABLE rules ADD COLUMN IF NOT EXISTS description TEXT;

-- +goose StatementEnd
