\set ON_ERROR_STOP on
SELECT 'CREATE DATABASE enterprise_ai_portal'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'enterprise_ai_portal')\gexec
