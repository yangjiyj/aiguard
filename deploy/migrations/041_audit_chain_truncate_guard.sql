-- 041_audit_chain_truncate_guard.sql
-- 补 WORM 防护：FOR EACH ROW trigger 不拦截 TRUNCATE，需 STATEMENT 级 trigger
-- 复用 033 已建的 audit_chain_worm() 函数

DROP TRIGGER IF EXISTS audit_chain_no_truncate ON audit_chain;
CREATE TRIGGER audit_chain_no_truncate BEFORE TRUNCATE ON audit_chain
    FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_worm();
