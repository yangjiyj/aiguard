-- Seed: Associate default admin user with default project
INSERT INTO project_users (project_id, user_id) VALUES ('project_default', 'user_admin') ON CONFLICT DO NOTHING;
