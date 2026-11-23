\set ON_ERROR_STOP on

INSERT INTO teams (id,tenant_id,name,path)
VALUES
  ('lab-research','tenant_default','Lab Research','/lab-research'),
  ('lab-marketing','tenant_default','Lab Marketing','/lab-marketing')
ON CONFLICT (id) DO NOTHING;

INSERT INTO providers (id,tenant_id,name,provider_type,status)
VALUES ('lab-provider','tenant_default','Lab Provider','openai','active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO models (id,provider_id,model_name,status)
VALUES
  ('lab-research-model','lab-provider','lab-research-model','active'),
  ('lab-marketing-model','lab-provider','lab-marketing-model','active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO team_models (team_id,model_id,allowed)
VALUES
  ('lab-research','lab-research-model',TRUE),
  ('lab-marketing','lab-marketing-model',TRUE)
ON CONFLICT (team_id,model_id) DO UPDATE SET allowed=EXCLUDED.allowed;

INSERT INTO identity_department_mappings
  (id,tenant_id,source_kind,source_id,match_type,match_value,target_department_id,priority,enabled)
VALUES
  ('lab-map-research','tenant_default','oidc','','groups','dept-research','lab-research',10,TRUE),
  ('lab-map-marketing','tenant_default','oidc','','groups','dept-marketing','lab-marketing',10,TRUE),
  ('lab-map-research-ad','tenant_default','oidc','','groups','dept-research-ad','lab-research',10,TRUE),
  ('lab-map-marketing-ad','tenant_default','oidc','','groups','dept-marketing-ad','lab-marketing',10,TRUE)
ON CONFLICT (id) DO UPDATE SET
  match_value=EXCLUDED.match_value,
  target_department_id=EXCLUDED.target_department_id,
  priority=EXCLUDED.priority,
  enabled=EXCLUDED.enabled;
