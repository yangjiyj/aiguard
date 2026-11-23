BEGIN;

-- A request row is inserted before its child evidence. Start from an explicit
-- empty projection; the child-table triggers below recompute it transactionally.
ALTER TABLE request_logs
    ALTER COLUMN has_customer_content SET DEFAULT false,
    ALTER COLUMN has_customer_request_body SET DEFAULT false,
    ALTER COLUMN has_customer_response_body SET DEFAULT false;

CREATE OR REPLACE FUNCTION jjdguard_refresh_request_customer_content_projection(
    p_tenant_id varchar,
    p_request_id varchar
)
RETURNS void
LANGUAGE sql
AS $$
    UPDATE request_logs rl
    SET has_customer_content = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role IN ('user', 'assistant')
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_request_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'user'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        has_customer_response_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND EXISTS (
                    SELECT 1
                    FROM content_logs cl
                    WHERE cl.tenant_id = rl.tenant_id
                      AND cl.request_id = rl.id
                      AND cl.role = 'assistant'
                      AND jjdguard_customer_content_text(cl.content)
                )
            )
        ),
        customer_content_rule_version = 1
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id;
$$;

CREATE OR REPLACE FUNCTION refresh_request_customer_content_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_tenant_id varchar(64);
    old_request_id varchar(64);
    new_tenant_id varchar(64);
    new_request_id varchar(64);
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        old_tenant_id := OLD.tenant_id;
        IF TG_TABLE_NAME = 'content_logs' THEN
            SELECT rl.request_id INTO old_request_id
            FROM request_logs rl
            WHERE rl.tenant_id = OLD.tenant_id AND rl.id = OLD.request_id;
        ELSE
            old_request_id := OLD.request_id;
        END IF;
        PERFORM jjdguard_refresh_request_customer_content_projection(old_tenant_id, old_request_id);
    END IF;

    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        new_tenant_id := NEW.tenant_id;
        IF TG_TABLE_NAME = 'content_logs' THEN
            SELECT rl.request_id INTO new_request_id
            FROM request_logs rl
            WHERE rl.tenant_id = NEW.tenant_id AND rl.id = NEW.request_id;
        ELSE
            new_request_id := NEW.request_id;
        END IF;
        IF TG_OP <> 'UPDATE'
           OR old_tenant_id IS DISTINCT FROM new_tenant_id
           OR old_request_id IS DISTINCT FROM new_request_id THEN
            PERFORM jjdguard_refresh_request_customer_content_projection(new_tenant_id, new_request_id);
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_content_logs_customer_content_projection ON content_logs;
CREATE TRIGGER trg_content_logs_customer_content_projection
AFTER INSERT OR DELETE OR UPDATE OF tenant_id, request_id, role, content
ON content_logs
FOR EACH ROW
EXECUTE FUNCTION refresh_request_customer_content_projection();

DROP TRIGGER IF EXISTS trg_access_content_logs_customer_content_projection ON access_content_logs;
CREATE TRIGGER trg_access_content_logs_customer_content_projection
AFTER INSERT OR DELETE OR UPDATE OF tenant_id, request_id, request_content_redacted,
    response_content_redacted, file_metadata_json
ON access_content_logs
FOR EACH ROW
EXECUTE FUNCTION refresh_request_customer_content_projection();

DROP TRIGGER IF EXISTS trg_request_logs_customer_content_projection ON request_logs;
CREATE TRIGGER trg_request_logs_customer_content_projection
AFTER UPDATE OF proxy_mode
ON request_logs
FOR EACH ROW
WHEN (OLD.proxy_mode IS DISTINCT FROM NEW.proxy_mode)
EXECUTE FUNCTION refresh_request_customer_content_projection();

COMMIT;
