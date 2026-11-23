-- 032_pause_log_key_prefix_extend.sql
-- 扩 pause_log.key_prefix 长度，与其他 key 字段对齐

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'pause_log' AND column_name = 'key_prefix'
      AND character_maximum_length = 32
  ) THEN
    ALTER TABLE pause_log ALTER COLUMN key_prefix TYPE VARCHAR(64);
  END IF;
END $$;

COMMENT ON COLUMN pause_log.key_prefix IS 'API Key 前缀（扩到 64 字符，与 quota_policies.key_prefix 对齐）';
