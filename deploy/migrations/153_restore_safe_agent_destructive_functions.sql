-- pg_restore deliberately uses an empty search_path while loading archive
-- data. These CHECK functions call each other, so bind their lookup path
-- explicitly; otherwise a valid custom-format backup cannot restore rows into
-- agent_destructive_policies.
DO $$
BEGIN
    IF to_regprocedure('public.agent_destructive_json_string_array_valid(jsonb)') IS NOT NULL THEN
        EXECUTE 'ALTER FUNCTION public.agent_destructive_json_string_array_valid(jsonb) SET search_path TO pg_catalog, public';
    END IF;
    IF to_regprocedure('public.agent_destructive_paths_valid(jsonb)') IS NOT NULL THEN
        EXECUTE 'ALTER FUNCTION public.agent_destructive_paths_valid(jsonb) SET search_path TO pg_catalog, public';
    END IF;
    IF to_regprocedure('public.initialize_agent_destructive_policies_from_legacy(boolean)') IS NOT NULL THEN
        EXECUTE 'ALTER FUNCTION public.initialize_agent_destructive_policies_from_legacy(boolean) SET search_path TO pg_catalog, public';
    END IF;
END
$$;
