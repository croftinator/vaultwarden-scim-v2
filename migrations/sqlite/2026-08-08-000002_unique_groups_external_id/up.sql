-- See the postgresql migration of the same name for the full reasoning.
UPDATE groups
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND uuid NOT IN (
		SELECT MIN(uuid)
		FROM groups
		WHERE external_id IS NOT NULL
		GROUP BY organizations_uuid, external_id
	);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_org_external_id_unique
	ON groups (organizations_uuid, external_id);
