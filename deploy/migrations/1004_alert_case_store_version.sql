-- 1004_alert_case_store_version: 告警案件物化口径的版本记录（2.9.22 批次 7）。
--
-- alert_case_members / alert_cases 存的是控制面按当时的归并 SQL 算出的结果。控制面把这段 SQL（以及是否
-- 使用生成列 alert_read_metadata_v1）算成指纹记在这里；以后哪个版本改了归并口径，启动后发现指纹不同，
-- 就把所有租户的回填重置、重建物化结果，重建完成前读接口照旧实时查询，不会用旧口径的结果。
-- 只建一张单行表。回滚：deploy/migrations/rollback/1004_alert_case_store_version.sql。

CREATE TABLE IF NOT EXISTS alert_case_store_version (
    id             BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    logic_version  TEXT        NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT alert_case_store_version_single_row CHECK (id)
);
