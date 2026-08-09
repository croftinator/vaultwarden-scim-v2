CREATE INDEX IF NOT EXISTS idx_users_organizations_org_external_id
	ON users_organizations (org_uuid, external_id);
