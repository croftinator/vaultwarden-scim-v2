CREATE INDEX IF NOT EXISTS idx_groups_org_external_id
	ON "groups" (organizations_uuid, external_id);
