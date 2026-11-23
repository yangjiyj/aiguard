package modelaccess

import "context"

// SchemaReady guards the migration contract used by every owned Key request.
func SchemaReady(ctx context.Context, db Queryer) (bool, error) {
	var ready bool
	err := db.QueryRow(ctx, `SELECT NOT EXISTS(
 SELECT 1 FROM (VALUES ('employee_api_keys','issued_role'),('employee_api_keys','tenant_id'),('employee_api_keys','user_id'),('employee_api_keys','key_id'),('users','id'),('users','tenant_id'),('users','role'),('users','status'),('users','department_id'),('users','department_version'),('users','department_assignment_mode'),('teams','id'),('teams','tenant_id'),('teams','name'),('teams','system_key'),('teams','model_access_mode'),('providers','id'),('providers','tenant_id'),('models','id'),('models','provider_id'),('models','model_name'),('user_model_policies','user_id'),('user_model_policies','tenant_id'),('user_model_policies','mode'),('user_model_policies','model_names'),('user_model_policies','version'),('user_model_extra_grants','id'),('user_model_extra_grants','tenant_id'),('user_model_extra_grants','user_id'),('user_model_extra_grants','model'),('user_model_extra_grants','reason'),('user_model_extra_grants','expires_at'),('user_model_extra_grants','created_by'),('user_model_extra_grants','created_at'),('user_model_extra_grants','revoked_at')) required(table_name,column_name)
 WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
 WHERE a.attrelid=to_regclass(required.table_name) AND a.attname=required.column_name AND a.attnum>0 AND NOT a.attisdropped)
 )`).Scan(&ready)
	return ready, err
}
