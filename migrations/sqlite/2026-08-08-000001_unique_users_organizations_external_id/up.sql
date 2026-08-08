-- See the postgresql migration of the same name for the full reasoning. sqlite
-- agrees with postgresql on both points that matter here: NULLs are distinct in
-- a UNIQUE index, and CREATE UNIQUE INDEX IF NOT EXISTS is supported.
UPDATE users_organizations
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT MIN(uuid)
		FROM users_organizations
		WHERE external_id IS NOT NULL
		GROUP BY org_uuid, external_id
	);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_organizations_org_external_id_unique
	ON users_organizations (org_uuid, external_id);
