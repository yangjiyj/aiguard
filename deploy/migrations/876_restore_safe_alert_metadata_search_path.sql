BEGIN;

-- pg_restore clears search_path before COPY recomputes stored generated columns.
-- Bind the helper lookup without changing function bodies or other settings.
ALTER FUNCTION public.jjd_alert_read_metadata_v1(jsonb)
  SET search_path TO pg_catalog, public, pg_temp;
ALTER FUNCTION public.jjd_alert_read_metadata_v2(jsonb)
  SET search_path TO pg_catalog, public, pg_temp;

COMMIT;
