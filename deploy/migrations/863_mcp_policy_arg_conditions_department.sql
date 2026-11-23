-- W1 1.12: MCP policy argument conditions + department scope.
--
-- arg_conditions: JSON array of {path, op, value}; all must hold for the policy
-- to match. Empty array (the default for every existing row) keeps the old
-- behaviour exactly. Evaluated by the gateway against tools/call arguments;
-- tool arguments are never sent to the control plane.
--
-- scope_type 'department' matches users.department_id of the calling user
-- (resolved by the control plane from user_id). Rank: user > department > project.
ALTER TABLE mcp_policies ADD COLUMN IF NOT EXISTS arg_conditions JSONB NOT NULL DEFAULT '[]'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mcp_policies_arg_conditions_array_check') THEN
    ALTER TABLE mcp_policies
      ADD CONSTRAINT mcp_policies_arg_conditions_array_check
      CHECK (jsonb_typeof(arg_conditions) = 'array' AND jsonb_array_length(arg_conditions) <= 8);
  END IF;
END
$$;

ALTER TABLE mcp_policies DROP CONSTRAINT IF EXISTS mcp_policies_scope_type_check;
ALTER TABLE mcp_policies
  ADD CONSTRAINT mcp_policies_scope_type_check
  CHECK (scope_type IN ('tenant','project','department','user','key','agent','session'));

COMMENT ON COLUMN mcp_policies.arg_conditions IS
  'W1 1.12: tools/call argument conditions [{path,op,value}], AND-ed; empty = argument-independent. Only for target_kind tool';
COMMENT ON COLUMN mcp_policies.scope_type IS
  'Scope tier: session>key>agent>user>department>project>tenant; department matches users.department_id';
