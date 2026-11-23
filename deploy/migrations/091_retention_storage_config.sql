-- 091_retention_storage_config.sql
-- +goose Up
-- 留存存储后端配置(单例,全局)。控制台可改、proxy-server 读它实例化 local/s3 后端。
-- S3 secret 加密存(secrets.EncryptProviderSecret,enc:v1: 前缀,绝不明文落库)。
-- local 根路径仍走 env RETENTION_STORE_PATH(基础设施级),不进这表。
CREATE TABLE IF NOT EXISTS retention_storage_config (
    id            text PRIMARY KEY DEFAULT 'singleton',
    backend       text NOT NULL DEFAULT 'local',
    local_path    text NOT NULL DEFAULT '',
    s3_endpoint   text NOT NULL DEFAULT '',
    s3_bucket     text NOT NULL DEFAULT '',
    s3_access_key text NOT NULL DEFAULT '',
    s3_secret_enc text NOT NULL DEFAULT '',
    s3_region     text NOT NULL DEFAULT '',
    s3_prefix     text NOT NULL DEFAULT '',
    s3_use_ssl    boolean NOT NULL DEFAULT true,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    text NOT NULL DEFAULT '',
    CONSTRAINT retention_storage_config_singleton CHECK (id = 'singleton')
);

INSERT INTO retention_storage_config (id, backend) VALUES ('singleton', 'local')
ON CONFLICT (id) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS retention_storage_config;
