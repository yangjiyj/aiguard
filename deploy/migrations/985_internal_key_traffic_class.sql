-- 985: 给接入凭据增加「流量类别」标记，供安全告警按车道分流使用。
--
-- traffic_class 取值：
--   ''           默认，普通业务流量（行为与旧版本完全一致）
--   'evaluation' 测评/红队流量：该凭据产生的攻击样本进入告警页的「测评流量」车道
--   'coding'     编程助手流量：内容规则类命中进入「观察」车道
-- 只有管理员能设置，告警页的车道判定只信这一列，不信凭据名称或请求头。
-- 车道只改变显示分组，不删除、不抑制、不改变任何检测结果与执行模式。
-- 列带默认值且 NOT NULL，存量行自动取 ''，旧版本不读取该列，保留列无害；回退见 +goose Down 与 rollback/985。
ALTER TABLE internal_keys
  ADD COLUMN IF NOT EXISTS traffic_class text NOT NULL DEFAULT '';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'internal_keys_traffic_class_check') THEN
    ALTER TABLE internal_keys
      ADD CONSTRAINT internal_keys_traffic_class_check CHECK (traffic_class IN ('', 'evaluation', 'coding'));
  END IF;
END $$;

-- +goose Down
ALTER TABLE internal_keys DROP CONSTRAINT IF EXISTS internal_keys_traffic_class_check;
ALTER TABLE internal_keys DROP COLUMN IF EXISTS traffic_class;
