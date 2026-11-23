-- +goose Up
-- +goose StatementBegin

-- ============================================================
-- App Management Refactoring Migration
-- Enhances project_users and projects tables for better app management
-- ============================================================

-- 1. 修改 project_users 表结构
-- 先添加 id 列（允许为空，稍后填充）
ALTER TABLE project_users ADD COLUMN IF NOT EXISTS id VARCHAR(32);
ALTER TABLE project_users ADD COLUMN IF NOT EXISTS role VARCHAR(16) DEFAULT 'developer';

-- 为现有记录生成 id
UPDATE project_users SET id = 'pu_' || substr(gen_random_uuid()::text, 1, 28) WHERE id IS NULL;

-- 将 id 设置为非空并设为主键
-- 注意：PostgreSQL 不允许直接修改主键，需要先删除再添加
-- 这里我们创建一个唯一索引来确保 id 唯一，然后添加主键约束

-- 创建序列用于生成 id（可选，但便于管理）
-- 如果 id 列已存在且有值，跳过更新
DO $$
BEGIN
    -- 检查是否存在没有 id 的记录
    IF EXISTS (SELECT 1 FROM project_users WHERE id IS NULL) THEN
        UPDATE project_users SET id = 'pu_' || substr(gen_random_uuid()::text, 1, 28) WHERE id IS NULL;
    END IF;
END $$;

-- 设置 id 为非空
ALTER TABLE project_users ALTER COLUMN id SET NOT NULL;

-- 添加主键约束（如果不存在）
DO $$
BEGIN
    -- 先检查是否已有主键约束
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'project_users_pkey' AND contype = 'p'
    ) THEN
        -- 如果当前主键是复合键 (project_id, user_id)，我们需要重新定义
        -- 但由于可能已有数据，这里采用更安全的方式
        -- 添加 UNIQUE 约束到 id 列
        EXECUTE 'ALTER TABLE project_users ADD CONSTRAINT project_users_id_key UNIQUE (id)';
    END IF;
END $$;

-- 添加索引
CREATE INDEX IF NOT EXISTS idx_project_users_project ON project_users(project_id);
CREATE INDEX IF NOT EXISTS idx_project_users_user ON project_users(user_id);

-- 设置默认值（确保新记录自动生成 id）
ALTER TABLE project_users ALTER COLUMN id SET DEFAULT 'pu_' || substr(gen_random_uuid()::text, 1, 28);

-- 2. projects 表新增字段
ALTER TABLE projects ADD COLUMN IF NOT EXISTS model_whitelist JSONB DEFAULT '[]'::jsonb;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS quota_limits JSONB DEFAULT '{}'::jsonb;

-- Note: Down migrations are not executed in Docker entrypoint
-- They are only used by goose migration tool for rollback
