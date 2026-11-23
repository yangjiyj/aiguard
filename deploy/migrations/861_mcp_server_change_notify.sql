-- W1 1.10: notify gateways when an mcp_servers row changes so the 60s route
-- cache is invalidated immediately (disable / delete / re-route take effect on
-- the next request). Payload is tenant_id || chr(31) || id, matching the
-- gateway cache key. NOTIFY is delivered on commit only, so rolled-back
-- changes never invalidate anything. Gateways that are not listening keep the
-- old 60s TTL behaviour.
CREATE OR REPLACE FUNCTION notify_mcp_server_changed() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP IN ('UPDATE','DELETE') THEN
    PERFORM pg_notify('jjd_mcp_server_changed', OLD.tenant_id || chr(31) || OLD.id);
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.tenant_id, NEW.id) IS DISTINCT FROM (OLD.tenant_id, OLD.id) THEN
    PERFORM pg_notify('jjd_mcp_server_changed', NEW.tenant_id || chr(31) || NEW.id);
  END IF;
  RETURN NULL;
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_mcp_server_changed_notify ON mcp_servers;
CREATE TRIGGER trg_mcp_server_changed_notify AFTER UPDATE OR DELETE ON mcp_servers
FOR EACH ROW EXECUTE FUNCTION notify_mcp_server_changed();

COMMENT ON FUNCTION notify_mcp_server_changed() IS
  'W1 1.10: pg_notify jjd_mcp_server_changed with tenant_id||chr(31)||id so gateways drop cached MCP routes immediately';
