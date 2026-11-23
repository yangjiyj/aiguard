ALTER TABLE internal_keys ADD COLUMN IF NOT EXISTS agent_instance_id varchar(128);
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS agent_instance_id varchar(128);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS agent_instance_id varchar(128);




-- Materialize only at write time from an immutable authenticated key ID.
-- This covers legacy audit adapters as well as direct agent-aware writers.
CREATE OR REPLACE FUNCTION tri_materialize_agent_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='request_logs' THEN
   IF NEW.agent_instance_id IS NULL THEN
     SELECT k.agent_instance_id INTO NEW.agent_instance_id FROM internal_keys k
      WHERE k.id=NEW.client_id AND k.tenant_id=NEW.tenant_id;
   END IF;
 ELSE
   IF NEW.agent_instance_id IS NULL THEN
     SELECT r.agent_instance_id INTO NEW.agent_instance_id FROM request_logs r
      WHERE r.request_id=NEW.request_id AND r.tenant_id=NEW.tenant_id;
   END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS tri_request_agent_identity ON request_logs;
CREATE TRIGGER tri_request_agent_identity BEFORE INSERT ON request_logs FOR EACH ROW EXECUTE FUNCTION tri_materialize_agent_identity();
DROP TRIGGER IF EXISTS tri_event_agent_identity ON security_events;
CREATE TRIGGER tri_event_agent_identity BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION tri_materialize_agent_identity();

CREATE OR REPLACE FUNCTION tri_agent_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.agent_instance_id IS DISTINCT FROM NEW.agent_instance_id THEN
   RAISE EXCEPTION 'agent binding is immutable';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS tri_agent_binding_immutable ON internal_keys;
CREATE TRIGGER tri_agent_binding_immutable BEFORE UPDATE OF agent_instance_id ON internal_keys FOR EACH ROW EXECUTE FUNCTION tri_agent_binding_immutable();
