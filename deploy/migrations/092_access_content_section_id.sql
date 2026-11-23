-- 092: access_content_logs 增加 section_id（turn 级分组键）。
-- 在线安全：nullable、无 default、无表重写。conversation_id/model 列已存在（061），仅 section_id 缺失。
ALTER TABLE access_content_logs ADD COLUMN IF NOT EXISTS section_id VARCHAR(128);
