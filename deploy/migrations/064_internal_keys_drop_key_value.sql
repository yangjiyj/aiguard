-- Migration: 064_internal_keys_drop_key_value
-- Purpose: 移除 internal_keys 的明文密钥列 key_value。
--          内部 key 鉴权仅依赖 key_hash（sha256），明文列为历史漂移列，
--          存在即构成密钥泄漏面（控制面列表曾回显明文）。本次彻底删除。
-- Part of: P0-1 内部 key 哈希存储与一次性明示（阶段二 Task 2.1，支柱⑤）
-- Note: 本仓库无运行时 migration runner；此文件用于变更留痕，
--       需在目标库手工执行（幂等，IF EXISTS）。
ALTER TABLE internal_keys DROP COLUMN IF EXISTS key_value;
