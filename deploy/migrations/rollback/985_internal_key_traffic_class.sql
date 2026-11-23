ALTER TABLE internal_keys DROP CONSTRAINT IF EXISTS internal_keys_traffic_class_check;
ALTER TABLE internal_keys DROP COLUMN IF EXISTS traffic_class;
