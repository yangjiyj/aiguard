-- Dedicated gateway-native machine identity; no human department or SSO binding.
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_department_assignment_mode;
ALTER TABLE users ADD CONSTRAINT chk_users_department_assignment_mode CHECK (department_assignment_mode IN ('automatic','manual','unassigned','emergency','service'));
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_department_required;
ALTER TABLE users ADD CONSTRAINT chk_users_department_required CHECK (department_id IS NOT NULL OR department_assignment_mode='emergency' OR (department_assignment_mode='service' AND role='platform_connector'));
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_service_assignment_role;
ALTER TABLE users ADD CONSTRAINT chk_users_service_assignment_role CHECK (department_assignment_mode <> 'service' OR (role='platform_connector' AND department_id IS NULL));
