-- 名单外模型在记录档放行时的可检索标记。
ALTER TABLE request_logs ADD COLUMN policy_note text NOT NULL DEFAULT '';
